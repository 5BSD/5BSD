import subprocess

import pytest
from atf_python.ktest import BaseKernelTest


def _vtiommu_attached():
    return subprocess.run(["sysctl", "-n", "dev.vtiommu.0.%driver"],
                          capture_output=True).returncode == 0


# The test detaches and reattaches vtiommu0, which exists only in a guest
# booted with a virtio-iommu and hw.virtio_iommu.enable=1.
pytestmark = pytest.mark.skipif(not _vtiommu_attached(),
                                reason="needs an attached vtiommu0")


class TestVirtioIommuIdentity(BaseKernelTest):
    """Run the in-kernel virtio-iommu identity domain regressions."""

    KTEST_MODULE_NAME = "ktest_virtio_iommu"
