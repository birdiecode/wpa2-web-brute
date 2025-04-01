async function calc_pmk(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const derivedKey = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: enc.encode(salt),
            iterations: 4096,
            hash: "SHA-1",
        },
        keyMaterial,
        32 * 8
    );

    return new Uint8Array(derivedKey);
}

async function calc_ptk(key, B) {
    const blen = 64;
    let i = 0;
    let R = new Uint8Array();

    while (i <= ((blen * 8 + 159) / 160)) {
        const data = new Uint8Array(23 + B.length + 1);
        data.set([0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x00], 0);
        data.set(B, 23);
        data.set([i], 23 + B.length);

        const hmacKey = await crypto.subtle.importKey(
            "raw",
            key,
            { name: "HMAC", hash: { name: "SHA-1" } },
            false,
            ["sign"]
        );

        const hash = new Uint8Array(
            await crypto.subtle.sign("HMAC", hmacKey, data)
        );

        let newR = new Uint8Array(R.length + hash.length);
        newR.set(R);
        newR.set(hash, R.length);
        R = newR;

        i += 1;
    }

    return R.slice(0, blen);
}



const ssid = "Test_WiFi";
const test_password = "QWERTY12";
const key_data = new Uint8Array([0x60, 0xF6, 0x77, 0x00, 0xA9, 0xBA, 0x66, 0x4B, 0x93, 0x37, 0x28, 0x0F, 0xA6, 0x4A, 0xD5, 0x33, 0xD8, 0x74, 0x95, 0xC1, 0x16, 0x34, 0xC0, 0x1F, 0x4E, 0x37, 0xD8, 0x7B, 0x0D, 0x54, 0x14, 0x38, 0x2B, 0xB4, 0x79, 0x1F, 0x51, 0xE3, 0x15, 0xA7, 0x8C, 0x98, 0xB8, 0x7C, 0xEA, 0x03, 0xD0, 0x25, 0x93, 0x58, 0x63, 0xDF, 0xCC, 0x4A, 0x06, 0xA7, 0x62, 0x10, 0xFC, 0x5F, 0x53, 0x81, 0xF0, 0x51, 0x29, 0x3B, 0x27, 0x67, 0x83, 0x52, 0xE1, 0x67, 0xF7, 0x20, 0xF9, 0x9E]);


(async () => {
    const pmk = await calc_pmk(test_password, ssid);
    console.log("PMK: " + Array.from(pmk)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""));

    const ptk = await calc_ptk(pmk, key_data);
    console.log("PTK: " + Array.from(ptk)
        .map(b => b.toString(16).padStart(2, "0"))
        .join(""))

})();



