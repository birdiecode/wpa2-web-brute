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

async function calc_mic(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        key,
        { name: "HMAC", hash: { name: "SHA-1" } },
        false,
        ["sign"]
    );

    const signature = await crypto.subtle.sign("HMAC", cryptoKey, message);
    return new Uint8Array(signature).slice(0, 16);
}

function gen_pwd(index, lenpwd, chrary) {
    let res = [];

    for (let i = lenpwd - 1; i >= 0; i--) {
        let chrCalc = Math.floor(index / chrary.length ** i);
        index = index % chrary.length ** i;
        res.push(chrary[chrCalc]);
    }

    return res.join("");
}

async function fetchJson(url, method = 'GET', body = null) {
    try {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' }
        };
        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(url, options);
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        return data;
    } catch (error) {
        console.error("Ошибка при получении данных:", error);
        return null;
    }
}

(async () => {
    var data = await fetchJson('http://127.0.0.1:8000/task');
    var ret_hash = [];
    const key_data = new Uint8Array(data.key_data);
    const wpa2_data = new Uint8Array(data.wpa2_data);
    for(var pwd_int = data.start;  pwd_int <= data.start+data.col; pwd_int++){
        var pwd = gen_pwd(pwd_int, 8, ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']);
        console.log("PWD: "+pwd);

        var pmk = await calc_pmk(pwd, data.ssid);
        console.log("PMK: " + Array.from(pmk)
            .map(b => b.toString(16).padStart(2, "0"))
            .join(""));

        var ptk = await calc_ptk(pmk, key_data);
        console.log("PTK: " + Array.from(ptk)
            .map(b => b.toString(16).padStart(2, "0"))
            .join(""));

        var mic_gen = await calc_mic(ptk.slice(0, 16), wpa2_data);

        var mic_hex = Array.from(mic_gen).map(b => b.toString(16).padStart(2, "0")).join("");
        ret_hash.push(mic_hex);
        if(mic_hex===data.mic){
            fetchJson('http://127.0.0.1:8000/ret', 'POST', { key: data.start, data: pwd});
        }
        console.log("MIC: " + mic_hex);
    }

    var data2 = await fetchJson('http://127.0.0.1:8000/ret', 'POST', { key: data.start, data: "not find"});
    console.log(data2);



})();



