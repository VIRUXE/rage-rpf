#[cfg(test)]
mod writer_tests {
    use crate::archive::{RpfArchive, RpfEncryption};
    use crate::writer::RpfBuilder;

    fn roundtrip(encryption: RpfEncryption) {
        let mut builder = RpfBuilder::new(encryption);
        builder.add_file("hello.txt", b"Hello, world!".to_vec());
        builder.add_file("subdir/data.bin", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        builder.add_file("subdir/nested/deep.bin", b"deep file".to_vec());

        let bytes = builder.build(None).expect("build failed");

        let archive = RpfArchive::parse(&bytes, "test.rpf", None).expect("parse failed");
        assert_eq!(archive.entries.iter().filter(|e| e.is_file()).count(), 3);

        // verify file names are present
        let names: Vec<&str> = archive.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"hello.txt"), "missing hello.txt");
        assert!(names.contains(&"data.bin"), "missing data.bin");
        assert!(names.contains(&"deep.bin"), "missing deep.bin");

        // verify we can extract a file
        let entry = archive.entries.iter().find(|e| e.name == "hello.txt").unwrap();
        let extracted = archive.extract_entry(&bytes, entry, None).expect("extract failed");
        assert_eq!(extracted, b"Hello, world!");
    }

    #[test]
    fn roundtrip_open() {
        roundtrip(RpfEncryption::Open);
    }

    #[test]
    fn roundtrip_none() {
        roundtrip(RpfEncryption::None);
    }

    #[test]
    fn empty_archive() {
        let builder = RpfBuilder::new(RpfEncryption::Open);
        let bytes = builder.build(None).expect("build failed");
        let archive = RpfArchive::parse(&bytes, "empty.rpf", None).expect("parse failed");
        assert_eq!(archive.entries.len(), 1); // root dir only
    }
}
