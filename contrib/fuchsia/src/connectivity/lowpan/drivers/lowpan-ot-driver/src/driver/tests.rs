// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::*;

use super::host_to_thread::NETSTACK_PACKET_ORIGIN;
use assert_matches::assert_matches;
use fuchsia_sync::Mutex;
use futures::prelude::*;
use lowpan_driver_common::Driver as _;
use lowpan_driver_common::lowpan_fidl::{
    ConnectivityState, Credential, Identity, NET_TYPE_THREAD_1_X, ProvisioningParams,
};
use lowpan_driver_common::net::*;
use lowpan_driver_common::spinel::mock::*;
use lowpan_driver_common::spinel::*;
use openthread::ot::{Ip6 as _, MessageBuffer as _, Nat64 as _, Trel};
use openthread_fuchsia::Platform;
use packet::{
    InnerPacketBuilder as _, NestableSerializer as _, NoOpSerializationContext, Serializer as _,
};
use packet_formats::ip::{IpProto, Ipv6Proto};
use packet_formats::ipv6::Ipv6PacketBuilder;
use packet_formats::udp::UdpPacketBuilder;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::sync::{Arc, LazyLock};

static TEST_HARNESS_SINGLETON_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

static TEST_IDENTITY: LazyLock<Identity> = LazyLock::new(|| Identity {
    raw_name: Some("MyNetwork".as_bytes().to_vec()),
    xpanid: Some([0, 1, 2, 3, 4, 5, 6, 7]),
    net_type: Some(NET_TYPE_THREAD_1_X.to_string()),
    channel: Some(13),
    panid: Some(0x1234),
    ..Default::default()
});

static TEST_CREDENTIAL: LazyLock<Credential> = LazyLock::new(|| {
    Credential::NetworkKey(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
});

const DEFAULT_TEST_TIMEOUT: MonotonicDuration = MonotonicDuration::from_seconds(45);

/// This method is our test harness for all of our individual tests.
/// It sets up a fake radio and fake network interface and allows
/// the program flow to be tested in a fairly straightforward manner.
fn test_harness<'a, Fun, Fut>(fun: Fun) -> impl Future<Output = ()> + Send + 'a
where
    Fun: FnOnce(Arc<OtDriver<OtInstanceBox, DummyNetworkInterface, DummyBackboneInterface>>) -> Fut,
    Fut: Future<Output = ()> + Send + 'a,
{
    // Since OpenThread is a singleton, we can't create more than once instance at a time.
    // This lock makes sure that we only run a single test at a time so we don't panic.
    let _singleton_lock = TEST_HARNESS_SINGLETON_LOCK.lock();

    let (sink, stream, ncp_task) = new_fake_spinel_pair();

    // The following task must ultimately run in the background on
    // a separate thread in order for the OpenThread Fuchsia platform
    // to work properly. When used with the multithreaded executor,
    // this `spawn` call does the trick.
    let ncp_task = fasync::Task::spawn(ncp_task);

    let network_interface = DummyNetworkInterface::default();
    let backbone_interface = DummyBackboneInterface::default();

    // Queue a network event that indicates we are enabled.
    network_interface.set_enabled(true).now_or_never().unwrap().unwrap();

    let instance = ot::Instance::new(Platform::build().init(sink, stream));

    // Ignore all persistent storage.
    instance.erase_persistent_info().unwrap();

    // Explicitly turn off services like TREL and SRP by default for tests.
    // If needed, it can be enabled in the individual tests.
    instance.trel_set_enabled(false);
    instance.srp_server_set_enabled(false);
    instance.srp_server_set_auto_enable_mode(false);

    ot::set_logging_level(ot::LogLevel::Crit);

    // Create a publisher proxy and server end.  The server end behavior is not currently tested,
    // so simply drop it.
    let (publisher, _) =
        fidl::endpoints::create_proxy::<fidl_fuchsia_net_mdns::ServiceInstancePublisherMarker>();
    let (sender, receiver) = mpsc::channel(100);
    let (border_agent_sender, border_agent_receiver) = mpsc::channel(10);

    let driver = Arc::new(OtDriver::new(
        instance,
        network_interface,
        backbone_interface,
        ProductMetadata::default(),
        sender,
        border_agent_sender,
    ));

    // Note that we cannot move this into an async block because
    // `fun` itself doesn't implement `Send`.
    let app_task = fun(driver.clone());

    let driver_clone = driver.clone();
    let app_task = async move {
        // Wait for the driver to handle the call to `network_interface.set_enabled(true)`
        // before moving on.
        driver_clone
            .wait_for_state(DriverState::is_active)
            .on_timeout(fasync::MonotonicInstant::after(DEFAULT_TEST_TIMEOUT), || {
                panic!("Initialization timed out");
            })
            .await;
        app_task
            .on_timeout(fasync::MonotonicInstant::after(DEFAULT_TEST_TIMEOUT), || {
                panic!("App task timed out");
            })
            .await;
    };

    async move {
        let driver_stream = driver.main_loop_stream(receiver, border_agent_receiver, publisher);

        let mut driver_stream_count = 0u32;
        futures::select_biased! {
            ret = driver_stream.try_for_each(move |_| {
                driver_stream_count += 1;
                assert!(driver_stream_count < 1000, "STUCK: Driver stream had 10^3 iterations");
                futures::future::ready(Ok(()))
            }).fuse()
                => panic!("Driver stream error: {ret:?}"),
            ret = ncp_task.fuse()
                => panic!("NCP task error: {ret:?}"),
            _ = app_task.boxed().fuse() => (),
        }

        // Turn off OpenThread logging so that we don't see
        // the useless errors that crop up when we shutdown.
        ot::set_logging_level(ot::LogLevel::None);
    }
}

/// This is just a simple test where we bring everything up and
/// immediately tear it down. If this fails there are fundamental problems.
#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_driver_setup_and_teardown() {
    test_harness(|_| async move {}).await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_initial_device_state() {
    test_harness(|driver| async move {
        let mut device_state_stream = driver.watch_device_state();
        let mut identity_stream = driver.watch_identity();

        assert_eq!(
            device_state_stream
                .try_next()
                .await
                .expect("Error in device state stream")
                .expect("Device state stream ended unexpectedly")
                .connectivity_state
                .expect("Connectivity state missing from device state"),
            ConnectivityState::Offline
        );

        assert!(device_state_stream.next().now_or_never().is_none());

        let new_identity = identity_stream
            .try_next()
            .await
            .expect("Error in identity stream")
            .expect("Identity stream ended unexpectedly");
        assert_eq!(new_identity, Identity::default());

        assert!(identity_stream.next().now_or_never().is_none());
    })
    .await;
}

#[fuchsia::test(threads = 10)]
#[ignore] // TODO: Re-enable once scan support is added to test RCP
async fn test_network_scan() {
    test_harness(|driver| async move {
        let network_scan_stream = driver.start_network_scan(
            &lowpan_driver_common::lowpan_fidl::NetworkScanParameters::default(),
        );
        assert_eq!(network_scan_stream.try_collect::<Vec<_>>().await.unwrap().len(), 3);
    })
    .await;
}

#[fuchsia::test(threads = 10)]
#[ignore] // TODO: Re-enable once joiner support is added to test RCP
async fn test_joiner() {
    use lowpan_driver_common::lowpan_fidl::{JoinParams, JoinerCommissioningParams};

    test_harness(|driver| async move {
        let join_stream =
            driver.join_network(JoinParams::JoinerParameter(JoinerCommissioningParams {
                pskd: Some("ABCDEFG".to_string()),
                ..Default::default()
            }));
        join_stream.try_collect::<Vec<_>>().await.unwrap();
    })
    .await;
}

#[fuchsia::test(threads = 10)]
#[ignore] // TODO: Re-enable once scan support is added to test RCP
async fn test_energy_scan() {
    test_harness(|driver| async move {
        let energy_scan_stream = driver
            .start_energy_scan(&lowpan_driver_common::lowpan_fidl::EnergyScanParameters::default());
        assert_eq!(energy_scan_stream.try_collect::<Vec<_>>().await.unwrap().len(), 3);
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_supported_channels() {
    test_harness(|driver| async move {
        let channels = driver.get_supported_channels().await;
        assert_eq!(channels.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_factory_mac_address() {
    test_harness(|driver| async move {
        let fact_mac = driver.get_factory_mac_address().await;
        assert_eq!(fact_mac.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_current_mac_address() {
    test_harness(|driver| async move {
        let fact_mac = driver.get_current_mac_address().await;
        assert_eq!(fact_mac.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_supported_network_types() {
    test_harness(|driver| async move {
        let network_types = driver.get_supported_network_types().await;
        assert_eq!(
            network_types,
            Ok(vec![lowpan_driver_common::lowpan_fidl::NET_TYPE_THREAD_1_X.to_string()])
        );
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_current_channel() {
    test_harness(|driver| async move {
        let curr_chan = driver.get_current_channel().await;
        assert_eq!(curr_chan.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_partition_id() {
    test_harness(|driver| async move {
        let part_id = driver.get_partition_id().await;
        assert_eq!(part_id.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_current_rssi() {
    test_harness(|driver| async move {
        let curr_rssi = driver.get_current_rssi().await;
        assert_eq!(curr_rssi.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_thread_rloc16() {
    test_harness(|driver| async move {
        let thread_rloc16 = driver.get_thread_rloc16().await;
        assert_eq!(thread_rloc16.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_thread_router_id() {
    test_harness(|driver| async move {
        let thread_router_id = driver.get_thread_router_id().await;
        assert_eq!(thread_router_id.map(|_| ()), Ok(()));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_neighbor_table_offline() {
    test_harness(|driver| async move {
        let thread_neighbor_table = driver.get_neighbor_table().await;
        assert_eq!(thread_neighbor_table, Ok(vec![]));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_get_counters() {
    test_harness(|driver| async move {
        let thread_counters = driver.get_counters().await;
        assert!(thread_counters.is_ok());
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_provision_network_offline() {
    test_harness(|driver| async move {
        let mut identity_stream = driver.watch_identity();

        assert_eq!(driver.set_active(false).await, Ok(()));

        assert_eq!(
            driver
                .provision_network(ProvisioningParams {
                    identity: TEST_IDENTITY.clone(),
                    credential: Some(Box::new(TEST_CREDENTIAL.clone())),
                })
                .await,
            Ok(())
        );

        assert_eq!(
            driver
                .watch_device_state()
                .try_next()
                .await
                .expect("Error in device state stream")
                .expect("Device state stream ended unexpectedly")
                .connectivity_state
                .expect("Connectivity state missing from device state"),
            ConnectivityState::Ready
        );

        let new_identity = identity_stream
            .try_next()
            .await
            .expect("Error in identity stream")
            .expect("Identity stream ended unexpectedly");
        assert_eq!(
            new_identity.raw_name.map(ot::NetworkName::try_from),
            TEST_IDENTITY.raw_name.clone().map(ot::NetworkName::try_from)
        );
        assert_eq!(new_identity.xpanid, TEST_IDENTITY.xpanid);
        assert_eq!(new_identity.panid, TEST_IDENTITY.panid);
        assert_eq!(new_identity.channel, TEST_IDENTITY.channel);
        assert_eq!(new_identity.net_type, TEST_IDENTITY.net_type);

        assert_eq!(driver.get_credential().await, Ok(Some(TEST_CREDENTIAL.clone())));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
async fn test_provision_network_online() {
    test_harness(|driver| async move {
        let mut device_state_stream = driver.watch_device_state();
        let mut identity_stream = driver.watch_identity();

        assert_eq!(
            device_state_stream
                .try_next()
                .await
                .expect("Error in device state stream")
                .expect("Device state stream ended unexpectedly")
                .connectivity_state
                .expect("Connectivity state missing from device state"),
            ConnectivityState::Offline
        );

        assert_eq!(
            driver
                .provision_network(ProvisioningParams {
                    identity: TEST_IDENTITY.clone(),
                    credential: Some(Box::new(TEST_CREDENTIAL.clone())),
                })
                .await,
            Ok(())
        );

        info!("Waiting to become 'Attaching'");
        assert_eq!(
            device_state_stream
                .try_next()
                .await
                .expect("Error in device state stream")
                .expect("Device state stream ended unexpectedly")
                .connectivity_state
                .expect("Connectivity state missing from device state"),
            ConnectivityState::Attaching
        );

        info!("Waiting to become 'Attached'");
        assert_eq!(
            device_state_stream
                .try_next()
                .await
                .expect("Error in device state stream")
                .expect("Device state stream ended unexpectedly")
                .connectivity_state
                .expect("Connectivity state missing from device state"),
            ConnectivityState::Attached
        );

        let new_identity = identity_stream
            .try_next()
            .await
            .expect("Error in identity stream")
            .expect("Identity stream ended unexpectedly");
        assert_eq!(
            new_identity.raw_name.map(ot::NetworkName::try_from),
            TEST_IDENTITY.raw_name.clone().map(ot::NetworkName::try_from)
        );
        assert_eq!(new_identity.xpanid, TEST_IDENTITY.xpanid);
        assert_eq!(new_identity.panid, TEST_IDENTITY.panid);
        assert_eq!(new_identity.channel, TEST_IDENTITY.channel);
        assert_eq!(new_identity.net_type, TEST_IDENTITY.net_type);

        assert_eq!(driver.get_credential().await, Ok(Some(TEST_CREDENTIAL.clone())));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
#[allow(clippy::or_fun_call)]
async fn test_add_on_mesh_prefix() {
    test_harness(|driver| async move {
        assert_eq!(
            driver
                .provision_network(ProvisioningParams {
                    identity: TEST_IDENTITY.clone(),
                    credential: Some(Box::new(TEST_CREDENTIAL.clone())),
                })
                .await,
            Ok(())
        );

        assert_eq!(driver.set_active(true).await, Ok(()));

        driver.wait_for_state(DriverState::is_active_and_ready).await;

        let on_mesh_prefix_subnet: lowpan_driver_common::lowpan_fidl::Ipv6Subnet =
            Subnet { addr: std::net::Ipv6Addr::from_str("2001:DB8::").unwrap(), prefix_len: 64 }
                .into();
        let x = lowpan_driver_common::lowpan_fidl::OnMeshPrefix {
            subnet: Some(on_mesh_prefix_subnet),
            slaac_preferred: Some(true),
            slaac_valid: Some(true),
            ..Default::default()
        };
        assert_eq!(driver.register_on_mesh_prefix(x.clone()).await, Ok(()));

        assert_eq!(
            driver
                .get_local_on_mesh_prefixes()
                .map(|x| x.context("get_local_on_mesh_prefixes"))
                .and_then(|x| futures::future::ready(
                    x.first().ok_or(format_err!("on-mesh-prefixes is empty")).map(|x| x.subnet)
                ))
                .await
                .unwrap(),
            x.subnet
        );
        assert_eq!(driver.unregister_on_mesh_prefix(on_mesh_prefix_subnet).await, Ok(()));
        assert_eq!(driver.get_local_on_mesh_prefixes().await, Ok(vec![]));
    })
    .await;
}

#[ignore]
#[fuchsia::test(threads = 10)]
#[allow(clippy::or_fun_call)]
async fn test_add_external_route() {
    test_harness(|driver| async move {
        assert_eq!(
            driver
                .provision_network(ProvisioningParams {
                    identity: TEST_IDENTITY.clone(),
                    credential: Some(Box::new(TEST_CREDENTIAL.clone())),
                })
                .await,
            Ok(())
        );

        driver.wait_for_state(DriverState::is_active_and_ready).await;

        let external_route_subnet: lowpan_driver_common::lowpan_fidl::Ipv6Subnet =
            Subnet { addr: std::net::Ipv6Addr::from_str("2001:DB8::").unwrap(), prefix_len: 64 }
                .into();
        let x = lowpan_driver_common::lowpan_fidl::ExternalRoute {
            subnet: Some(external_route_subnet),
            route_preference: Some(lowpan_driver_common::lowpan_fidl::RoutePreference::Medium),
            stable: Some(true),
            ..Default::default()
        };
        assert_eq!(driver.register_external_route(x.clone()).await, Ok(()));

        fuchsia_async::Timer::new(fuchsia_async::MonotonicDuration::from_millis(50)).await;

        assert_eq!(
            driver
                .get_local_external_routes()
                .map(|x| x.context("get_local_external_routes"))
                .and_then(|x| futures::future::ready(
                    x.first()
                        .ok_or(format_err!("local_external_routes is empty"))
                        .map(|x| x.subnet)
                ))
                .await
                .unwrap(),
            x.subnet
        );
        assert_eq!(driver.unregister_external_route(external_route_subnet).await, Ok(()));
        assert_eq!(driver.get_local_external_routes().await, Ok(vec![]));
    })
    .await;
}

#[fuchsia::test(threads = 10)]
#[ignore] // TODO(fxrev.dev/92419): Remove this once <fxrev.dev/92419> is fixed.
#[allow(clippy::or_fun_call)]
async fn test_grind_lowpan_ot_driver() {
    test_harness(|driver| async move {
        let mut device_state_stream = driver.watch_device_state();
        let mut identity_stream = driver.watch_identity();

        assert_eq!(
            device_state_stream.try_next().await.unwrap().unwrap().connectivity_state.unwrap(),
            ConnectivityState::Offline
        );

        debug!("app_task: Making sure it only vends one state when nothing has changed.");
        assert!(device_state_stream.next().now_or_never().is_none());

        for i in 1u8..32 {
            debug!("app_task: Starting Iteration {}", i);

            debug!("app_task: Setting disabled...");
            assert_eq!(driver.set_active(false).await, Ok(()));
            debug!("app_task: Did disable!");

            let channels = driver.get_supported_channels().await;
            debug!("app_task: Supported channels: {:?}", channels);
            assert_eq!(channels.map(|_| ()), Ok(()));

            let fact_mac = driver.get_factory_mac_address().await;
            debug!("app_task: Factory MAC: {:?}", fact_mac);
            assert_eq!(fact_mac.map(|_| ()), Ok(()));

            let curr_mac = driver.get_current_mac_address().await;
            debug!("app_task: Current MAC: {:?}", curr_mac);
            assert_eq!(curr_mac.map(|_| ()), Ok(()));

            let ncp_ver = driver.get_ncp_version().await;
            debug!("app_task: NCP Version: {:?}", ncp_ver);
            assert_eq!(ncp_ver.map(|_| ()), Ok(()));

            let network_types = driver.get_supported_network_types().await;
            debug!("app_task: Supported Network Types: {:?}", network_types);
            assert_eq!(
                network_types,
                Ok(vec![lowpan_driver_common::lowpan_fidl::NET_TYPE_THREAD_1_X.to_string()])
            );

            let curr_chan = driver.get_current_channel().await;
            debug!("app_task: Current Channel: {:?}", curr_chan);
            assert_eq!(curr_chan.map(|_| ()), Ok(()));

            let curr_rssi = driver.get_current_rssi().await;
            debug!("app_task: Current RSSI: {:?}", curr_rssi);
            assert_eq!(curr_rssi.map(|_| ()), Ok(()));

            let part_id = driver.get_partition_id().await;
            debug!("app_task: partition id: {:?}", part_id);
            assert_eq!(part_id.map(|_| ()), Ok(()));

            let thread_rloc16 = driver.get_thread_rloc16().await;
            debug!("app_task: thread_rloc16: {:?}", thread_rloc16);
            assert_eq!(thread_rloc16.map(|_| ()), Ok(()));

            let thread_router_id = driver.get_thread_router_id().await;
            debug!("app_task: thread_router_id: {:?}", thread_router_id);
            assert_eq!(thread_router_id.map(|_| ()), Ok(()));

            let thread_neighbor_table = driver.get_neighbor_table().await;
            debug!("app_task: thread_neighbor_table: {:?}", thread_neighbor_table);
            let _thread_neighbor_entry_vec = thread_neighbor_table.unwrap();

            debug!("app_task: Attempting a reset...");
            assert_eq!(driver.reset().await, Ok(()));
            debug!("app_task: Did reset!");

            debug!("app_task: Checking device state... (Should be Inactive) (1)");
            assert_eq!(
                driver
                    .watch_device_state()
                    .try_next()
                    .await
                    .expect("Error in device state stream")
                    .expect("Device state stream ended unexpectedly")
                    .connectivity_state
                    .expect("Connectivity state missing from device state"),
                ConnectivityState::Inactive
            );

            debug!("app_task: Setting identity...");
            assert_eq!(
                driver
                    .provision_network(ProvisioningParams {
                        identity: TEST_IDENTITY.clone(),
                        credential: Some(Box::new(TEST_CREDENTIAL.clone())),
                    })
                    .await,
                Ok(())
            );
            debug!("app_task: Did provision!");

            debug!("app_task: Checking device state... (Should be Ready)");
            assert_eq!(
                driver
                    .watch_device_state()
                    .try_next()
                    .await
                    .expect("Error in device state stream")
                    .expect("Device state stream ended unexpectedly")
                    .connectivity_state
                    .expect("Connectivity state missing from device state"),
                ConnectivityState::Ready
            );

            debug!("app_task: Checking identity...");
            let new_identity = identity_stream
                .try_next()
                .await
                .expect("Error in identity stream")
                .expect("Identity stream ended unexpectedly");
            assert_eq!(
                new_identity.raw_name.map(ot::NetworkName::try_from),
                TEST_IDENTITY.raw_name.clone().map(ot::NetworkName::try_from)
            );
            assert_eq!(new_identity.xpanid, TEST_IDENTITY.xpanid);
            assert_eq!(new_identity.panid, TEST_IDENTITY.panid);
            assert_eq!(new_identity.channel, TEST_IDENTITY.channel);
            assert_eq!(new_identity.net_type, TEST_IDENTITY.net_type);
            debug!("app_task: Identity is correct!");

            debug!("app_task: Checking credential...");
            assert_eq!(driver.get_credential().await, Ok(Some(TEST_CREDENTIAL.clone())));
            debug!("app_task: Credential is correct!");

            debug!("app_task: Setting enabled...");
            assert_eq!(driver.set_active(true).await, Ok(()));
            debug!("app_task: Did enable!");

            debug!("app_task: Checking on-mesh prefixes to make sure it is empty...");
            assert_eq!(driver.get_local_on_mesh_prefixes().await, Ok(vec![]));
            debug!("app_task: Is empty!");

            debug!("app_task: Adding an on-mesh prefix...");
            let on_mesh_prefix_subnet: lowpan_driver_common::lowpan_fidl::Ipv6Subnet = Subnet {
                addr: std::net::Ipv6Addr::from_str("2001:DB8::").unwrap(),
                prefix_len: 64,
            }
            .into();
            let x = lowpan_driver_common::lowpan_fidl::OnMeshPrefix {
                subnet: Some(on_mesh_prefix_subnet),
                slaac_preferred: Some(true),
                slaac_valid: Some(true),
                ..Default::default()
            };
            assert_eq!(driver.register_on_mesh_prefix(x.clone()).await, Ok(()));
            debug!("app_task: Registered!");

            debug!("app_task: Checking on-mesh prefixes...");
            assert_eq!(
                driver
                    .get_local_on_mesh_prefixes()
                    .map(|x| x.context("get_local_on_mesh_prefixes"))
                    .and_then(|x| futures::future::ready(
                        x.first().ok_or(format_err!("on-mesh-prefixes is empty")).map(|x| x.subnet)
                    ))
                    .await
                    .unwrap(),
                x.subnet
            );
            debug!("app_task: Populated!");

            debug!("app_task: Removing an on-mesh prefix...");
            assert_eq!(driver.unregister_on_mesh_prefix(on_mesh_prefix_subnet).await, Ok(()));
            debug!("app_task: Unregistered!");

            debug!("app_task: Checking on-mesh prefixes to make sure it is empty...");
            assert_eq!(driver.get_local_on_mesh_prefixes().await, Ok(vec![]));
            debug!("app_task: Is empty!");

            debug!("app_task: Checking device state... (Should be Attaching)");
            assert_eq!(
                device_state_stream
                    .try_next()
                    .await
                    .expect("Error in device state stream")
                    .expect("Device state stream ended unexpectedly")
                    .connectivity_state
                    .unwrap(),
                ConnectivityState::Attaching
            );

            debug!("app_task: Setting disabled...");
            assert_eq!(driver.set_active(false).await, Ok(()));
            debug!("app_task: Did disable!");

            debug!("app_task: Checking device state... (Should be Ready)");
            assert_eq!(
                device_state_stream
                    .try_next()
                    .await
                    .expect("Error in device state stream")
                    .expect("Device state stream ended unexpectedly")
                    .connectivity_state
                    .unwrap(),
                ConnectivityState::Ready
            );

            debug!("app_task: Leaving network...");
            assert_eq!(driver.leave_network().await, Ok(()));
            debug!("app_task: Did leave!");

            debug!("app_task: Checking device state... (Should be Inactive)");
            assert_eq!(
                device_state_stream.try_next().await.unwrap().unwrap().connectivity_state.unwrap(),
                ConnectivityState::Inactive
            );

            debug!("app_task: Setting enabled...");
            assert_eq!(driver.set_active(true).await, Ok(()));
            debug!("app_task: Did enable!");

            debug!("app_task: Checking device state... (Should be Offline)");
            assert_eq!(
                device_state_stream.try_next().await.unwrap().unwrap().connectivity_state.unwrap(),
                ConnectivityState::Offline
            );

            debug!("app_task: Setting disabled...");
            assert_eq!(driver.set_active(false).await, Ok(()));
            debug!("app_task: Did disable!");

            debug!("app_task: Checking device state... (Should be Inactive) (2)");
            assert_eq!(
                device_state_stream.try_next().await.unwrap().unwrap().connectivity_state.unwrap(),
                ConnectivityState::Inactive
            );

            debug!("app_task: Finished Iteration {}", i);
        }
    })
    .await;
}

// Tests for the host-to-Thread trust boundary (https://fxbug.dev/521638028).
//
// Packets that netstack writes to the Thread TUN interface may have been forwarded
// from the untrusted infrastructure link, so OpenThread must treat them as
// `OT_MESSAGE_ORIGIN_HOST_UNTRUSTED`. These tests send such packets through the
// same `ip6_send_data` helper, with the same `NETSTACK_PACKET_ORIGIN`, used by
// `on_netstack_packet_for_thread` and check that OpenThread receives them with
// that origin.

/// Default hop limit used for the synthesized IPv6 packets.
const TEST_HOP_LIMIT: u8 = 64;

/// IPv6 next-header value for an encapsulated IPv6 packet (IPv6-in-IPv6).
const IPV6_IN_IPV6_NEXT_HEADER: u8 = 41;

/// UDP port used by the Thread Management Framework (TMF).
const TMF_UDP_PORT: NonZeroU16 = NonZeroU16::new(61631).unwrap();

/// Arbitrary UDP port that is not the TMF port.
const NON_TMF_UDP_PORT: NonZeroU16 = NonZeroU16::new(5683).unwrap();

/// Payload carried by the synthesized UDP datagrams.
const UDP_TEST_PAYLOAD: [u8; 4] = [0; 4];

/// Address of a host on the infrastructure (Wi-Fi/Ethernet) link.
const LAN_HOST_ADDR: net_types::ip::Ipv6Addr = net_declare::net_ip_v6!("2001:db8:1::1");

/// Off-mesh-routable style address of a remote Thread node.
const REMOTE_NODE_ADDR: net_types::ip::Ipv6Addr = net_declare::net_ip_v6!("2001:db8:2::1");

/// Link-local address used as the inner source of an encapsulated TMF request.
const INNER_SRC_LINK_LOCAL_ADDR: net_types::ip::Ipv6Addr = net_declare::net_ip_v6!("fe80::1");

/// Link-local address of a Thread neighbor.
const NEIGHBOR_LINK_LOCAL_ADDR: net_types::ip::Ipv6Addr = net_declare::net_ip_v6!("fe80::2");

/// Builds an IPv6 packet from `src` to `dst` whose payload is `body`, where
/// `proto` identifies the type of `body`.
fn build_ipv6_packet(
    src: net_types::ip::Ipv6Addr,
    dst: net_types::ip::Ipv6Addr,
    proto: Ipv6Proto,
    body: &[u8],
) -> Vec<u8> {
    body.into_serializer()
        .wrap_in(Ipv6PacketBuilder::new(src, dst, TEST_HOP_LIMIT, proto))
        .serialize_vec_outer(&mut NoOpSerializationContext)
        .expect("failed to serialize IPv6 packet")
        .as_ref()
        .to_vec()
}

/// Builds an IPv6 packet from `src` to `dst` carrying a UDP datagram that uses
/// `port` as both its source and destination port.
fn build_udp_packet(
    src: net_types::ip::Ipv6Addr,
    dst: net_types::ip::Ipv6Addr,
    port: NonZeroU16,
) -> Vec<u8> {
    UDP_TEST_PAYLOAD
        .into_serializer()
        .wrap_in(UdpPacketBuilder::new(src, dst, Some(port), port))
        .wrap_in(Ipv6PacketBuilder::new(src, dst, TEST_HOP_LIMIT, Ipv6Proto::Proto(IpProto::Udp)))
        .serialize_vec_outer(&mut NoOpSerializationContext)
        .expect("failed to serialize UDP packet")
        .as_ref()
        .to_vec()
}

/// Runs `fun` against a real OpenThread instance backed by the fake spinel RCP.
///
/// Unlike `test_harness`, this does not start the driver. It only exercises the
/// `openthread_rust` send helpers that the driver uses for host-to-Thread traffic.
fn with_ot_instance(fun: impl FnOnce(&ot::Instance)) {
    // OpenThread is a singleton, so only one instance may exist at a time.
    let _singleton_lock = TEST_HARNESS_SINGLETON_LOCK.lock();

    let (sink, stream, ncp_task) = new_fake_spinel_pair();

    // The fake RCP must be serviced on another executor thread while the
    // instance is created and used.
    let _ncp_task = fasync::Task::spawn(ncp_task);

    let instance = ot::Instance::new(Platform::build().init(sink, stream));
    ot::set_logging_level(ot::LogLevel::Crit);

    fun(&instance);

    ot::set_logging_level(ot::LogLevel::None);

    // `instance` is dropped before `_ncp_task`, because locals drop in reverse
    // declaration order.
}

/// Builds an IPv6-in-IPv6 packet from a host on the infrastructure link to a
/// remote Thread node. The inner packet is a TMF request with link-local
/// addresses, which a Thread node accepts once it removes the outer header.
fn build_tunneled_tmf_packet() -> Vec<u8> {
    let inner_packet =
        build_udp_packet(INNER_SRC_LINK_LOCAL_ADDR, NEIGHBOR_LINK_LOCAL_ADDR, TMF_UDP_PORT);
    build_ipv6_packet(
        LAN_HOST_ADDR,
        REMOTE_NODE_ADDR,
        Ipv6Proto::from(IPV6_IN_IPV6_NEXT_HEADER),
        &inner_packet,
    )
}

/// A host packet that encapsulates another IPv6 packet (IPv6-in-IPv6) must be
/// dropped. Otherwise a host on the infrastructure link can tunnel a TMF request
/// with link-local addresses through the Border Router to a remote Thread node.
///
/// OpenThread only applies this check to untrusted host packets, so the same
/// packet sent with the trusted host origin is not dropped by it.
#[fuchsia::test(threads = 10)]
async fn test_host_ip6_in_ip6_packet_is_dropped() {
    let packet = build_tunneled_tmf_packet();

    with_ot_instance(|instance| {
        assert_matches!(
            instance.ip6_send_data(&packet, ot::message::Origin::HostTrusted),
            Err(ot::Error::NoRoute)
        );
        assert_matches!(
            instance.ip6_send_data(&packet, NETSTACK_PACKET_ORIGIN),
            Err(ot::Error::MessageDropped)
        );
    });
}

/// `ip6_send_data_direct` is also a host-to-Thread entry point, so it must drop
/// IPv6-in-IPv6 packets too.
#[fuchsia::test(threads = 10)]
async fn test_host_ip6_in_ip6_packet_sent_direct_is_dropped() {
    let packet = build_tunneled_tmf_packet();

    with_ot_instance(|instance| {
        assert_matches!(
            instance.ip6_send_data_direct(&packet, NETSTACK_PACKET_ORIGIN),
            Err(ot::Error::MessageDropped)
        );
    });
}

/// The send helpers must refuse to tag host data as coming from the Thread
/// network interface, since that would bypass OpenThread's host-origin checks.
#[fuchsia::test(threads = 10)]
async fn test_host_send_data_rejects_thread_netif_origin() {
    let packet = build_udp_packet(LAN_HOST_ADDR, NEIGHBOR_LINK_LOCAL_ADDR, NON_TMF_UDP_PORT);

    with_ot_instance(|instance| {
        let origin = ot::message::Origin::ThreadNetif;
        assert_matches!(instance.ip6_send_data(&packet, origin), Err(ot::Error::InvalidArgs));
        assert_matches!(
            instance.ip6_send_data_direct(&packet, origin),
            Err(ot::Error::InvalidArgs)
        );
        assert_matches!(
            instance.nat64_send_data_slice(&[0x45u8; 20], origin),
            Err(ot::Error::InvalidArgs)
        );
    });
}

/// `ip6_send` and `nat64_send` must reject a message tagged as coming from the
/// Thread network interface and free it rather than leak it.
#[fuchsia::test(threads = 10)]
async fn test_host_send_rejects_thread_netif_message_without_leaking() {
    let packet = build_udp_packet(LAN_HOST_ADDR, NEIGHBOR_LINK_LOCAL_ADDR, NON_TMF_UDP_PORT);

    with_ot_instance(|instance| {
        let free_buffers_before = instance.get_buffer_info().0.mFreeBuffers;

        let mut msg = ot::Message::ip6_new_from_bytes(instance, &packet, None)
            .expect("failed to allocate IPv6 message");
        msg.set_origin(ot::message::Origin::ThreadNetif);
        assert_matches!(instance.ip6_send(msg), Err(ot::Error::InvalidArgs));
        assert_eq!(instance.get_buffer_info().0.mFreeBuffers, free_buffers_before);

        let mut msg =
            ot::Message::ip4_new(instance, None).expect("failed to allocate IPv4 message");
        msg.set_origin(ot::message::Origin::ThreadNetif);
        assert_matches!(instance.nat64_send(msg), Err(ot::Error::InvalidArgs));
        assert_eq!(instance.get_buffer_info().0.mFreeBuffers, free_buffers_before);
    });
}
