use crate::management::reply::ResourceUnavailable;
use anyhow::{Context, Result, ensure};

#[derive(Default)]
pub(crate) struct Writer(pub Vec<u8>);
impl Writer {
    pub fn u32(&mut self, value: u32) {
        self.0.extend(value.to_be_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.0.extend(value.to_be_bytes());
    }
    pub fn bool(&mut self, value: bool) {
        self.u32(u32::from(value));
    }
    pub fn fixed(&mut self, bytes: &[u8]) {
        self.0.extend(bytes);
    }
    pub fn opaque(&mut self, bytes: &[u8]) {
        self.u32(u32::try_from(bytes.len()).expect("bounded XDR argument"));
        self.fixed(bytes);
        self.0.resize(self.0.len() + (4 - bytes.len() % 4) % 4, 0);
    }
    pub fn string(&mut self, text: &str) {
        self.opaque(text.as_bytes());
    }
}
pub(crate) fn build(write: impl FnOnce(&mut Writer)) -> Writer {
    let mut writer = Writer::default();
    write(&mut writer);
    writer
}
pub(crate) struct Reader {
    data: Vec<u8>,
    offset: usize,
}
impl Reader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
    pub fn fixed(&mut self, length: usize) -> Result<Vec<u8>> {
        let end = self
            .offset
            .checked_add(length)
            .context("XDR length overflow")?;
        let bytes = self
            .data
            .get(self.offset..end)
            .context("truncated XDR data")?
            .to_vec();
        self.offset = end;
        Ok(bytes)
    }
    pub fn skip(&mut self, length: usize) -> Result<()> {
        let end = self
            .offset
            .checked_add(length)
            .context("XDR length overflow")?;
        ensure!(end <= self.data.len(), "truncated XDR data");
        self.offset = end;
        Ok(())
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.fixed(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed(8)?.try_into().unwrap()))
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ResourceUnavailable("invalid XDR boolean").into()),
        }
    }
    pub fn opaque(&mut self, limit: usize) -> Result<Vec<u8>> {
        let length = self.u32()? as usize;
        ensure!(length <= limit, "XDR data exceeds its limit");
        let value = self.fixed(length)?;
        let padding = self.fixed((4 - length % 4) % 4)?;
        ensure!(padding.iter().all(|b| *b == 0), "invalid XDR padding");
        Ok(value)
    }
    pub fn string(&mut self, limit: usize) -> Result<String> {
        Ok(String::from_utf8(self.opaque(limit)?)?)
    }
    pub fn end(&self) -> Result<()> {
        ensure!(self.offset == self.data.len(), "unexpected XDR data");
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_xdr_vector_and_boundaries() {
        let mut w = Writer::default();
        w.u32(u32::MAX);
        w.u64(1u64 << 40);
        w.bool(true);
        w.string("目录");
        w.opaque(&[1, 2, 3]);
        assert_eq!(
            hex::encode(&w.0),
            "ffffffff00000100000000000000000100000006e79baee5bd9500000000000301020300"
        );
        let mut r = Reader::new(w.0);
        assert_eq!(r.u32().unwrap(), u32::MAX);
        assert_eq!(r.u64().unwrap(), 1u64 << 40);
        assert!(r.bool().unwrap());
        assert_eq!(r.string(4096).unwrap(), "目录");
        assert_eq!(r.opaque(8).unwrap(), [1, 2, 3]);
        r.end().unwrap();
        for bytes in [
            vec![255; 4],
            vec![0, 0, 0, 99],
            vec![0, 0, 0, 1, 1, 1, 0, 0],
        ] {
            assert!(Reader::new(bytes).opaque(8).is_err());
        }
        assert!(Reader::new(vec![1]).u64().is_err());
        assert!(Reader::new(vec![0, 0, 0, 2]).bool().is_err());
        assert!(
            Reader::new(vec![0, 0, 0, 1, 255, 0, 0, 0])
                .string(8)
                .is_err()
        );
    }
}
