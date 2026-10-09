import full, {
  WPA2WebCrypto,
  WPA2WebGL,
  WPA2WebGPU,
  WebGL2MIC,
  WebGL2PMK,
  WebGL2PTK,
  WebGPUMIC,
  WebGPUPMK,
  WebGPUPTK,
  calc_mic,
  calc_pmk,
  calc_ptk,
} from 'wpa2-web-brute';
import { WPA2WebCrypto as CryptoBackend, calc_pmk as calcPmkFromSubpath } from 'wpa2-web-brute/webcrypto';
import { WPA2WebGL as WebGLBackend } from 'wpa2-web-brute/webgl';
import { WPA2WebGPU as WebGPUBackend } from 'wpa2-web-brute/webgpu';

const bytes = new Uint8Array();
const keyData = new Uint8Array(76);
const message = new Uint8Array();

const pmk: Promise<Uint8Array> = calc_pmk('password', 'ssid');
const ptk: Promise<Uint8Array> = calc_ptk(bytes, keyData);
const mic: Promise<Uint8Array> = calc_mic(bytes, message);
const subpathPmk: Promise<Uint8Array> = calcPmkFromSubpath('password', 'ssid');

async function checkBackends() {
  const crypto = await WPA2WebCrypto.create();
  const cryptoResult = await crypto.derive(['password'], 'ssid', keyData, message);
  const cryptoSubpath = await CryptoBackend.create();
  await cryptoSubpath.derive(['password'], 'ssid', keyData, message);

  const webgl = await WPA2WebGL.create();
  const webglSubpath = await WebGLBackend.create();
  const webgpu = await WPA2WebGPU.create();
  const webgpuSubpath = await WebGPUBackend.create();
  const pmkBackend = await WebGPUPMK.create();
  const ptkBackend = await WebGPUPTK.create();
  const micBackend = await WebGPUMIC.create({ lite: true });
  const pmks = await pmkBackend.calculate(['password'], 'ssid');
  const ptks = await ptkBackend.calculate(pmks.pmks, keyData);
  const mics = await micBackend.calculate([ptks.ptks[0].subarray(0, 16)], message);
  const webglPmk = new WebGL2PMK();
  const webglPtk = new WebGL2PTK();
  const webglMic = new WebGL2MIC();
  await webglPmk.derive(['password'], 'ssid');
  await webglPtk.derive([bytes], keyData);
  await webglMic.derive([bytes], message);

  const fullResult = await full.WPA2WebCrypto.create();
  const fullDerived = await fullResult.derive(['password'], 'ssid', keyData, message);
  const allMics: Uint8Array[] = [...cryptoResult.mics, ...fullDerived.mics, ...mics.mics];
  void [ptk, mic, pmk, subpathPmk, webgl, webglSubpath, webgpu, webgpuSubpath, allMics];
}

void checkBackends;
