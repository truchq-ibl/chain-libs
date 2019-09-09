//extern crate memmap;

mod append;

pub use append::{Appender, Pos, PosSize};

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
