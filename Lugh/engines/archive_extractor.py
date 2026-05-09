"""
Lugh v3.0 - Archive Extractor (Recursive)
"""
import os, zipfile, tarfile, gzip, bz2, lzma, tempfile, shutil
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# ARCHIVE EXTRACTOR (RECURSIVE)
# ══════════════════════════════════════════════════════════════
ARCHIVE_EXTS = {'.zip','.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz','.gz','.bz2','.xz','.7z','.rar'}

class ArchiveExtractor:
    """Recursively extracts nested archives."""

    def __init__(self):
        self.results = []; self.stop_requested = False; self.max_depth = 10; self.max_files = 10000

    def extract(self, archive_path, output_dir, recursive=True, depth=0, prog_cb=None):
        self.results = []; self.stop_requested = False
        self._extract(Path(archive_path), Path(output_dir), recursive, depth, prog_cb)
        return self.results

    def _extract(self, arc, outdir, recursive, depth, prog_cb):
        if self.stop_requested: return
        if depth > self.max_depth:
            self.results.append({"file":str(arc),"status":"skipped","reason":f"Max depth {self.max_depth} reached","depth":depth})
            return
        if len(self.results) > self.max_files:
            self.stop_requested = True; return
        outdir.mkdir(parents=True, exist_ok=True)
        name = arc.name.lower(); extracted = []
        try:
            if zipfile.is_zipfile(str(arc)):
                extracted = self._do_zip(arc, outdir, depth)
            elif name.endswith(('.tar','.tar.gz','.tgz','.tar.bz2','.tbz2','.tar.xz','.txz')):
                extracted = self._do_tar(arc, outdir, depth)
            elif name.endswith('.gz') and not name.endswith('.tar.gz'):
                extracted = self._do_gz(arc, outdir, depth)
            elif name.endswith('.bz2') and not name.endswith('.tar.bz2'):
                extracted = self._do_bz2(arc, outdir, depth)
            elif name.endswith('.xz') and not name.endswith('.tar.xz'):
                extracted = self._do_xz(arc, outdir, depth)
            else:
                self.results.append({"file":str(arc),"status":"unsupported","reason":"Unknown archive format","depth":depth})
                return
        except Exception as e:
            self.results.append({"file":str(arc),"status":"error","reason":str(e),"depth":depth})
            return
        if prog_cb: prog_cb(len(self.results))
        # Recurse into nested archives
        if recursive:
            for ef in extracted:
                ep = Path(ef)
                if ep.is_file() and self._is_archive(ep):
                    sub_out = outdir / (ep.stem + "_extracted")
                    self._extract(ep, sub_out, recursive, depth+1, prog_cb)

    def _do_zip(self, arc, outdir, depth):
        extracted = []
        with zipfile.ZipFile(str(arc), 'r') as zf:
            for info in zf.infolist():
                if self.stop_requested: break
                if info.is_dir(): continue
                # Sanitize path
                safe = Path(info.filename).name
                if not safe: continue
                dest = outdir / safe
                try:
                    with zf.open(info) as src, open(dest,'wb') as dst:
                        dst.write(src.read())
                    extracted.append(str(dest))
                    self.results.append({"file":safe,"source":str(arc),"dest":str(dest),
                                         "size":info.file_size,"compressed":info.compress_size,
                                         "status":"ok","depth":depth})
                except Exception as e:
                    self.results.append({"file":safe,"source":str(arc),"status":"error","reason":str(e),"depth":depth})
        return extracted

    def _do_tar(self, arc, outdir, depth):
        extracted = []
        try:
            with tarfile.open(str(arc), 'r:*') as tf:
                for member in tf.getmembers():
                    if self.stop_requested: break
                    if not member.isfile(): continue
                    safe = Path(member.name).name
                    if not safe: continue
                    dest = outdir / safe
                    try:
                        f = tf.extractfile(member)
                        if f:
                            with open(dest,'wb') as dst: dst.write(f.read())
                            extracted.append(str(dest))
                            self.results.append({"file":safe,"source":str(arc),"dest":str(dest),
                                                 "size":member.size,"status":"ok","depth":depth})
                    except Exception as e:
                        self.results.append({"file":safe,"source":str(arc),"status":"error","reason":str(e),"depth":depth})
        except Exception as e:
            self.results.append({"file":str(arc),"status":"error","reason":str(e),"depth":depth})
        return extracted

    def _do_gz(self, arc, outdir, depth):
        stem = arc.stem if arc.stem != arc.name else arc.name + ".decompressed"
        dest = outdir / stem
        try:
            with gzip.open(str(arc),'rb') as gz, open(dest,'wb') as out:
                out.write(gz.read())
            self.results.append({"file":stem,"source":str(arc),"dest":str(dest),"status":"ok","depth":depth})
            return [str(dest)]
        except Exception as e:
            self.results.append({"file":str(arc),"status":"error","reason":str(e),"depth":depth}); return []

    def _do_bz2(self, arc, outdir, depth):
        stem = arc.stem if arc.stem != arc.name else arc.name + ".decompressed"
        dest = outdir / stem
        try:
            with bz2.open(str(arc),'rb') as bz, open(dest,'wb') as out:
                out.write(bz.read())
            self.results.append({"file":stem,"source":str(arc),"dest":str(dest),"status":"ok","depth":depth})
            return [str(dest)]
        except Exception as e:
            self.results.append({"file":str(arc),"status":"error","reason":str(e),"depth":depth}); return []

    def _do_xz(self, arc, outdir, depth):
        stem = arc.stem if arc.stem != arc.name else arc.name + ".decompressed"
        dest = outdir / stem
        try:
            with lzma.open(str(arc),'rb') as xz, open(dest,'wb') as out:
                out.write(xz.read())
            self.results.append({"file":stem,"source":str(arc),"dest":str(dest),"status":"ok","depth":depth})
            return [str(dest)]
        except Exception as e:
            self.results.append({"file":str(arc),"status":"error","reason":str(e),"depth":depth}); return []

    def _is_archive(self, fp):
        nm = fp.name.lower()
        for ext in ARCHIVE_EXTS:
            if nm.endswith(ext): return True
        try: return zipfile.is_zipfile(str(fp))
        except: return False

    def stop(self): self.stop_requested = True

    def stats(self):
        ok = sum(1 for r in self.results if r.get("status")=="ok")
        err = sum(1 for r in self.results if r.get("status")=="error")
        skip = sum(1 for r in self.results if r.get("status")=="skipped")
        depths = set(r.get("depth",0) for r in self.results)
        return {"total":len(self.results),"extracted":ok,"errors":err,"skipped":skip,"max_depth":max(depths) if depths else 0}

