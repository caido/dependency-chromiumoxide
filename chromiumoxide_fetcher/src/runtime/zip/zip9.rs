use std::fs;
use std::io::{self, Read, Seek};
use std::ops::{Deref, DerefMut};
use std::path::Path;

use zip9::{
    read::ZipFile,
    result::{ZipError, ZipResult},
};

#[derive(Clone, Debug)]
pub struct ZipArchive<R: Read + Seek>(zip9::ZipArchive<R>);

impl<R: Read + Seek> Deref for ZipArchive<R> {
    type Target = zip9::ZipArchive<R>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R: Read + Seek> DerefMut for ZipArchive<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<R: Read + Seek> ZipArchive<R> {
    pub fn new(reader: R) -> ZipResult<Self> {
        zip9::ZipArchive::new(reader).map(Self)
    }

    /// We need this custom extract function to support symlinks.
    /// This is based on https://github.com/zip-rs/zip/pull/213.
    ///
    /// We must be careful with this implementation since it is not
    /// protected against malicious symlinks, but we trust the binaries
    /// provided by chromium.
    pub fn extract<P: AsRef<Path>>(&mut self, directory: P) -> ZipResult<()> {
        for i in 0..self.len() {
            let mut file = self.by_index(i)?;

            let filepath = file
                .enclosed_name()
                .ok_or(ZipError::InvalidArchive("Invalid file path".into()))?;
            let outpath = directory.as_ref().join(filepath);

            if file.is_dir() {
                fs::create_dir_all(&outpath)?;
            } else {
                if let Some(p) = outpath.parent() {
                    if !p.exists() {
                        fs::create_dir_all(p)?;
                    }
                }

                match read_symlink(&mut file)? {
                    Some(target) => {
                        create_symlink(target, &outpath)?;
                    }
                    None => {
                        let mut outfile = fs::File::create(&outpath)?;
                        io::copy(&mut file, &mut outfile)?;

                        // Get and Set permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Some(mode) = file.unix_mode() {
                                fs::set_permissions(&outpath, fs::Permissions::from_mode(mode))?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn read_symlink<R: Read + ?Sized>(entry: &mut ZipFile<'_, R>) -> ZipResult<Option<Vec<u8>>> {
    if entry.is_symlink() {
        let mut contents = Vec::new();
        entry.read_to_end(&mut contents)?;
        return Ok(Some(contents));
    }
    Ok(None)
}

#[cfg(target_family = "unix")]
fn create_symlink(link_target: Vec<u8>, link_path: &Path) -> ZipResult<()> {
    use std::os::unix::ffi::OsStringExt as _;

    let link_target = std::ffi::OsString::from_vec(link_target);
    std::os::unix::fs::symlink(link_target, link_path)?;

    Ok(())
}

#[cfg(target_family = "windows")]
fn create_symlink(link_target: Vec<u8>, link_path: &Path) -> ZipResult<()> {
    // Only supports UTF-8 paths which is enough for our usecase
    let link_target = String::from_utf8(link_target)
        .map_err(|_| ZipError::InvalidArchive("Invalid symlink target name".into()))?;
    std::os::windows::fs::symlink_file(link_target, link_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use zip9::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    use super::*;

    fn fixture(build: impl FnOnce(&mut ZipWriter<Cursor<Vec<u8>>>)) -> ZipArchive<Cursor<Vec<u8>>> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        build(&mut writer);
        ZipArchive::new(writer.finish().unwrap()).unwrap()
    }

    fn file_options() -> SimpleFileOptions {
        SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(0o755)
    }

    #[test]
    fn extracts_files_and_directories() {
        let mut archive = fixture(|writer| {
            writer.add_directory("empty/", file_options()).unwrap();
            writer.start_file("bin/chrome", file_options()).unwrap();
            writer.write_all(b"browser fixture\n").unwrap();
            writer.start_file("resources/data", file_options()).unwrap();
            writer.write_all(b"resource fixture\n").unwrap();
        });
        let destination = tempfile::tempdir().unwrap();

        archive.extract(destination.path()).unwrap();

        assert!(destination.path().join("empty").is_dir());
        assert_eq!(
            fs::read(destination.path().join("bin/chrome")).unwrap(),
            b"browser fixture\n"
        );
        assert_eq!(
            fs::read(destination.path().join("resources/data")).unwrap(),
            b"resource fixture\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(destination.path().join("bin/chrome"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn extracts_relative_symlinks() {
        let mut archive = fixture(|writer| {
            writer.start_file("lib/target", file_options()).unwrap();
            writer.write_all(b"linked resource").unwrap();
            writer
                .add_symlink("lib/link", "target", file_options())
                .unwrap();
        });
        let destination = tempfile::tempdir().unwrap();

        archive.extract(destination.path()).unwrap();

        let link = destination.path().join("lib/link");
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("target"));
        assert_eq!(fs::read(link).unwrap(), b"linked resource");
    }

    #[test]
    fn contains_absolute_entry_paths() {
        let mut archive = fixture(|writer| {
            writer.start_file("/resource", file_options()).unwrap();
            writer.write_all(b"contained resource").unwrap();
        });
        let destination = tempfile::tempdir().unwrap();

        archive.extract(destination.path()).unwrap();

        assert_eq!(
            fs::read(destination.path().join("resource")).unwrap(),
            b"contained resource"
        );
    }

    #[test]
    fn rejects_paths_outside_destination() {
        for name in ["../outside", "nested/../../outside"] {
            let placeholder = "x".repeat(name.len());
            let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
            writer.start_file(&placeholder, file_options()).unwrap();
            writer.write_all(b"must not be extracted").unwrap();
            let mut bytes = writer.finish().unwrap().into_inner();
            // Write unsafe names into both headers without writer normalization.
            let mut replacements = 0;
            for offset in 0..=bytes.len() - placeholder.len() {
                if bytes[offset..].starts_with(placeholder.as_bytes()) {
                    bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
                    replacements += 1;
                }
            }
            assert_eq!(replacements, 2);
            let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
            let root = tempfile::tempdir().unwrap();
            let destination = root.path().join("extracted");
            fs::create_dir(&destination).unwrap();

            assert!(
                matches!(
                    archive.extract(&destination),
                    Err(ZipError::InvalidArchive(_))
                ),
                "entry {name:?} was not rejected"
            );
            assert!(!root.path().join("outside").exists());
            assert_eq!(fs::read_dir(destination).unwrap().count(), 0);
        }
    }
}
