#![no_main]
use libfuzzer_sys::fuzz_target;

// use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};
// // use target_rs::Foo;
//
// // fuzz_target!(|data: Foo| {
// //     if data.a == -559038737i32 && data.b == 0x11111111i32 && data.c == 0x22222222i32 {
// //         if data.s.len() == 100 {
// //             panic!("nooooooooo");
// //         }
// //     }
// // });
//
// fuzz_target!(|data: &[u8]| {
//     let mut buf = Unstructured::new(data);
//     let s = <[u8; 100]>::arbitrary(&mut buf).unwrap();
//     let a = i32::arbitrary(&mut buf).unwrap();
//     let b = i32::arbitrary(&mut buf).unwrap();
//     let c = i32::arbitrary(&mut buf).unwrap();
//     if (a == -559038737i32) && (b == 0x11111111i32) && (c == 0x22222222i32) {
//         if s.len() == 100 {
//             panic!("nooooooooo");
//         }
//     }
// });

fuzz_target!(|data: ([u8; 100], i32, i32, i32)| {
    let (s, a, b, c) = data;
    if (a == -559038737i32) && (b == 0x11111111i32) && (c == 0x22222222i32) {
        if s.len() == 100 {
            panic!("nooooooooo");
        }
    }
});
