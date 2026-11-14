# SPDX-License-Identifier: BSD-2-Clause
"""Construct a complete pkgbase ZFS disk without root, mounts or target execution."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import time
from construction_records import construction_records
from pkg_relocated import root_command


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def destination(value):
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//") or
            str(PurePosixPath(value)) != value or ".." in PurePosixPath(value).parts or
            any(c.isspace() or ord(c)<32 or ord(c)==127 for c in value)):
        raise ValueError("canonical whitespace-free absolute image path required")
    return value


def policy_check(policy):
    if type(policy.get("format")) is not int or policy["format"] != 1 or policy.get("filesystem") != "zfs" or policy.get("boot_mode") != "bios":
        raise ValueError("explicit format-1 BIOS/ZFS image policy required")
    if type(policy.get("size_bytes")) is not int or policy["size_bytes"] <= 0:
        raise ValueError("positive explicit image size required")
    if type(policy.get("epoch")) is not int or policy["epoch"] < 0:
        raise ValueError("nonnegative explicit image epoch required")
    for value in [policy["pool"], policy["bootfs"], *[d["name"] for d in policy["datasets"]]]:
        if not value or value.startswith("/") or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-/" for c in value) or ".." in value.split("/"):
            raise ValueError("valid explicit ZFS dataset identifier required")
    names = [d["name"] for d in policy["datasets"]]
    if len(names) != len(set(names)) or policy["pool"] not in names or policy["bootfs"] not in names:
        raise ValueError("distinct declared pool/boot datasets required")
    for entry in policy["datasets"]:
        for key, value in entry["properties"].items():
            if key not in ("mountpoint", "canmount", "exec", "setuid", "atime") or any(c in str(value) for c in ";,\n\r"):
                raise ValueError("unsupported dataset property")
    if set(policy["bootcode"]) != {"pmbr", "stage2"}:
        raise ValueError("explicit BIOS pmbr and stage2 bootcode required")
    if not re.fullmatch(r"[A-Za-z0-9_-]+",policy["repository_name"]):
        raise ValueError("explicit valid build catalogue name required")
    for value in policy["bootcode"].values():
        destination(value)
    for value in policy["generated_files"]:
        destination(value)
    for value, operation in policy["site_operations"].items():
        destination(value)
        if operation not in ("create", "prepend", "replace"):
            raise ValueError("explicit site create/prepend/replace operation required")


def main():
    request = json.loads(Path(sys.argv[1]).read_text())
    if request.get("format") != 1:
        raise ValueError("image request format 1 required")
    policy = json.loads(Path(request["policy"]).read_text());policy_check(policy)
    output, report_path, metalog = [Path(request[key]).absolute() for key in ("image", "report", "metalog")]
    for key in ("pkg", "makefs", "mkimg", "abi_file", "osversion_header"):
        request[key] = str(Path(request[key]).resolve(strict=True))
    runtime = sorted({str(Path(path).resolve(strict=True).parent) for path in request["runtime"]})
    index = json.loads(Path(request["index"]).read_text())
    catalogue = json.loads(Path(request["catalogue"]).read_text())
    inventory = json.loads(Path(request["inventory"]).read_text())
    payload = json.loads(Path(request["payload_inventory"]).read_text())
    archives = {Path(path).name: Path(path).resolve(strict=True) for path in request["packages"]}
    assert len(archives) == len(request["packages"])
    expected_archives = {catalogue["prefix"] + "-" + name + "-" + catalogue["version"] + ".pkg" for name in catalogue["packages"]}
    assert set(archives) == expected_archives == {entry["name"] for entry in index["packages"]}
    assert all(digest(archives[entry["name"]]) == entry["sha256"] for entry in index["packages"])
    records = {row["destination"]:row for rows in inventory["packages"].values() for row in rows if row["type"] != "dir"}
    directories = dict(inventory["shared_directories"])
    for rows in inventory["packages"].values():
        for row in rows:
            if row["type"] == "dir":directories.setdefault(row["destination"], row)
    construction = {row["destination"]:row for row in construction_records(
        request["construction"], request.get("construction_trees", []))}
    assert construction == inventory["construction"]
    site = {row["destination"]:row for row in request["site"]}
    assert len(site) == len(request["site"]) and set(site) == set(policy["site_operations"])
    for path, row in site.items():
        destination(path)
        if row["type"] != "file":raise ValueError("explicit regular site files required")
        operation = policy["site_operations"][path]
        if operation == "create":
            if path in records or path in construction or path in directories:raise ValueError("site create collides with base: " + path)
        elif path not in records or "config" not in records[path]["tags"]:
            raise ValueError("site replacement requires a declared package configuration file: " + path)
    if set(policy["generated_files"]) & (set(records)|set(construction)|set(site)|set(directories)):
        raise ValueError("generated state collides with declared image input")
    versions = re.findall(r"^#define\s+__FreeBSD_version\s+(\d+)\s*$",Path(request["osversion_header"]).read_text(),re.M)
    assert len(versions) == 1
    source_hashes = dict(payload["files"])
    commands = []
    with tempfile.TemporaryDirectory(prefix=".pkg-image-",dir=output.parent) as temporary:
        work = Path(temporary);stage = work/"root";stage.mkdir()
        # distrib-dirs contains legitimate unowned empty scaffolding that pkg
        # cannot create from package claims. Materialize every declared directory,
        # retaining intended ownership/modes in METALOG rather than host metadata.
        for path in sorted(directories,key=lambda path:len(PurePosixPath(path).parts)):
            destination(path)
            (stage/path.lstrip("/")).mkdir(mode=0o700,parents=True,exist_ok=True)
        repos=work/"repos";repos.mkdir();config=work/"pkg.conf";config.write_text("{}\n")
        env = {"LC_ALL":"C", "HOME":str(work), "TMPDIR":str(work), "LD_LIBRARY_PATH":":".join(runtime), "PATH":"/nonexistent", "INSTALL_AS_USER":"yes"}
        def run(label, argv, cwd=None):
            stdout=work/(label+".stdout");stderr=work/(label+".stderr");start=time.monotonic()
            actions=[(os.POSIX_SPAWN_OPEN,1,str(stdout),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600),
                (os.POSIX_SPAWN_OPEN,2,str(stderr),os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)]
            previous=Path.cwd()
            try:
                if cwd:os.chdir(cwd)
                pid=os.posix_spawn(str(argv[0]),list(map(str,argv)),env,file_actions=actions)
                _,status,usage=os.wait4(pid,0)
            finally:os.chdir(previous)
            entry=dict(phase=label,install_as_user=env["INSTALL_AS_USER"],argv=list(map(str,argv)),status=os.waitstatus_to_exitcode(status),seconds=time.monotonic()-start,
                user_seconds=usage.ru_utime,system_seconds=usage.ru_stime,maxrss_kib=usage.ru_maxrss,
                input_operations=usage.ru_inblock,output_operations=usage.ru_oublock)
            commands.append(entry)
            print("IMAGE_PHASE="+json.dumps(entry),flush=True)
            if entry["status"]:
                raise RuntimeError(label+" failed: "+stderr.read_text()[-12000:])
            return stdout.read_text()
        dbdir=work/"pkgdb"
        common=root_command(request["pkg"],stage,config,repos,dbdir=dbdir,cachedir=work/"cache")
        common.extend(["-o","IGNORE_OSVERSION=yes","-o","ASSUME_ALWAYS_YES=yes"])
        abi=run("abi",common+["-o","ABI_FILE="+request["abi_file"],"config","ABI"]).strip()
        assert abi and not any(c.isspace() for c in abi)
        common.extend(["-o","ABI="+abi,"-o","OSVERSION="+versions[0]])
        repository=work/"repository";repository.mkdir()
        for name,source in archives.items():shutil.copyfile(source,repository/name)
        repo_name=policy["repository_name"]
        (repos/"image.conf").write_text(json.dumps({repo_name:dict(url=repository.as_uri(),enabled=True,signature_type="none")})+"\n")
        repo_command=[request["pkg"],"-C",str(config),"-R",str(repos),"-o","PKG_DBDIR="+str(work/"catalogue-db"),
            "-o","PKG_CACHEDIR="+str(work/"catalogue-cache"),"-o","SYSLOG=no","-o","PKG_ENABLE_PLUGINS=no"]
        run("repository",repo_command+["repo","-l",str(repository)])
        run("catalogue",common+["update","-f","-r",repo_name])
        names=sorted(catalogue["prefix"]+"-"+name for name in catalogue["packages"])
        run("install",common+["install","-y","-U","-r",repo_name,*names])
        installed=run("installed",common+["query","-a","%n-%v"]).splitlines()
        assert sorted(installed)==sorted(catalogue["prefix"]+"-"+name+"-"+catalogue["version"] for name in catalogue["packages"])
        for path,row in construction.items():
            assert not row["tags"] and row["type"]=="file"
            target=stage/path.lstrip("/");assert not target.exists()
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(row["source"],target)
            target.chmod(int(row["mode"],8))
        allrecords=dict(records,**construction)
        site_hashes={}
        for path,row in site.items():
            target=stage/path.lstrip("/");assert target.parent.is_dir()
            data=Path(row["source"]).read_bytes()
            if policy["site_operations"][path]=="prepend":data+=b"\n"+target.read_bytes()
            target.write_bytes(data);target.chmod(int(row["mode"],8))
            site_hashes[path]=hashlib.sha256(data).hexdigest()
            allrecords[path]=row
        for path,metadata in policy["generated_files"].items():
            target=stage/path.lstrip("/")
            if metadata["producer"]!="pkg-local-database":raise ValueError("unsupported generated image state producer")
            source=dbdir/"local.sqlite";assert source.is_file() and not source.is_symlink()
            assert target.parent.is_dir() and not target.exists()
            shutil.copyfile(source,target)
            allrecords[path]=dict(metadata,destination=path,type="file",source=str(target),tags=[])
            source_hashes[str(target)]=dict(sha256=digest(target),size=target.stat().st_size)
        def account_map(path,count):
            result={}
            for line in (stage/path).read_text().splitlines():
                if not line or line.startswith("#"):continue
                fields=line.split(":");assert len(fields)==count and fields[0] not in result
                result[fields[0]]=int(fields[2])
            return result
        users=account_map("etc/master.passwd",10);groups=account_map("etc/group",4)
        expected=set(allrecords)|set(directories)
        observed={"/"}
        for parent,dirs,files in os.walk(stage,followlinks=False):
            for name in dirs+files:observed.add("/"+str((Path(parent)/name).relative_to(stage)))
        assert observed==expected,("unexplained completed image objects",sorted(observed-expected),sorted(expected-observed))
        hashes={};lines=[]
        for path,row in sorted(dict(directories,**allrecords).items()):
            destination(path);target=stage/path.lstrip("/");kind=row["type"]
            fields=["."+path if path!="/" else ".","type="+{"symlink":"link","hardlink":"file"}.get(kind,kind),
                "uid="+str(users[row["owner"]]),"gid="+str(groups[row["group"]]),"mode="+row["mode"],
                "flags="+(row.get("flags","") or "none"),"time="+str(policy["epoch"])+".0"]
            if kind=="dir":assert target.is_dir() and not target.is_symlink()
            elif kind=="symlink":assert target.is_symlink() and os.readlink(target)==row["link"];fields.append("link="+row["link"])
            else:
                assert target.is_file() and not target.is_symlink()
                source=row;seen=set()
                while source["type"]=="hardlink":
                    assert source["destination"] not in seen;seen.add(source["destination"]);source=allrecords[source["link"]]
                actual=digest(target);assert actual==(site_hashes[path] if path in site_hashes else source_hashes[source["source"]]["sha256"]),path;hashes[path]=actual
            lines.append(" ".join(fields)+"\n")
        metalog.write_text("".join(lines))
        filesystem=work/"root.zfs"
        argv=[request["makefs"],"-N",str(stage/"etc"),"-t","zfs","-s",str(policy["size_bytes"]),"-D","-B","little",
            "-o","poolname="+policy["pool"],"-o","bootfs="+policy["bootfs"],"-o","rootpath=/"]
        for dataset in policy["datasets"]:
            argv.extend(["-o","fs="+dataset["name"]+"".join(";"+key+"="+str(value) for key,value in dataset["properties"].items())])
        argv.extend([str(filesystem),str(metalog)])
        run("makefs",argv,cwd=stage)
        for path in policy["bootcode"].values():assert path in records and hashes[path]==source_hashes[records[path]["source"]]["sha256"]
        argv=[request["mkimg"],"-s","gpt","-f","raw","-b",str(stage/policy["bootcode"]["pmbr"].lstrip("/")),
            "-p","freebsd-boot/bootfs:="+str(stage/policy["bootcode"]["stage2"].lstrip("/")),
            "-p","freebsd-zfs/rootfs:="+str(filesystem),"-o",str(output)]
        run("mkimg",argv)
        report=dict(format=1,status="passed",scope="Complete package-derived rootless ZFS BIOS disk construction; not boot, installation ownership, verified boot or upgrade proof",
            packages=len(installed),files=len(allrecords),directories=len(directories),abi=abi,osversion=versions[0],
            filesystem=policy["filesystem"],pool=policy["pool"],bootfs=policy["bootfs"],datasets=policy["datasets"],
            policy_sha256=digest(request["policy"]),image_sha256=digest(output),image_bytes=output.stat().st_size,
            metalog_sha256=digest(metalog),commands=commands,payload_sha256=hashes,
            package_scripts="suppressed by INSTALL_AS_USER; declared construction outputs supplied; normal firstboot still requires VM qualification")
        report_path.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        for parent,dirs,files in os.walk(stage):
            for name in dirs:
                target=Path(parent)/name
                if not target.is_symlink():target.chmod(0o700)

if __name__=="__main__":
    main()
