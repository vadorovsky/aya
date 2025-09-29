use aya::{
    EbpfLoader,
    maps::{Array, HashMap},
    programs::UProbe,
};
use integration_common::hash_map::GET_INDEX;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn hash_map_insert(key: u32, value: u32) {
    std::hint::black_box((key, value));
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn hash_map_get(key: u32) {
    std::hint::black_box(key);
}

#[test_log::test]
fn test_hash_map() {
    let mut ebpf = EbpfLoader::new().load(crate::HASH_MAP).unwrap();
    for (result_map, hash_map, progs_and_symbols) in [
        // BTF map definitions.
        (
            "RESULT",
            "HASH_MAP",
            [("insert", "hash_map_insert"), ("get", "hash_map_get")],
        ),
        // Legacy map definitions.
        (
            "RESULT_LEGACY",
            "HASH_MAP_LEGACY",
            [
                ("insert_legacy", "hash_map_insert"),
                ("get_legacy", "hash_map_get"),
            ],
        ),
    ] {
        for (prog_name, symbol) in progs_and_symbols {
            let prog: &mut UProbe = ebpf.program_mut(prog_name).unwrap().try_into().unwrap();
            prog.load().unwrap();
            prog.attach(symbol, "/proc/self/exe", None, None).unwrap();
        }
        let result_array = ebpf.map(result_map).unwrap();
        let result_array = Array::<_, u32>::try_from(result_array).unwrap();
        let hash_map = ebpf.map(hash_map).unwrap();
        let hash_map = HashMap::<_, u32, u32>::try_from(hash_map).unwrap();
        let seq = 0_u32..9;
        for i in seq.clone() {
            hash_map_insert(i.pow(2), i);
        }
        for i in seq.clone() {
            // Assert the value returned by user-space API.
            let key = i.pow(2);
            let value = hash_map.get(&key, 0).unwrap();
            assert_eq!(value, i);
            // Assert the value returned by eBPF in-kernel API.
            hash_map_get(key);
            let result = result_array.get(&GET_INDEX, 0).unwrap();
            assert_eq!(result, i);
        }
    }
}
