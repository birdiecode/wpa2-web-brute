async function pmk(password, salt) {
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

    console.log(Array.from(new Uint8Array(derivedKey))
            .map(b => b.toString(16).padStart(2, "0"))
            .join(""));
}



var ssid = "Test_WiFi";
var test_password = "QWERTY12";

pmk(test_password, ssid);