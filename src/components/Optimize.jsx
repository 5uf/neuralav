import { createSignal, onCleanup } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import "./Optimize.css";

function Optimize() {
  const [displayMsg, setDisplayMsg] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  let timer;
  let disposed = false;
  async function run(command) {
    setBusy(true);
    setDisplayMsg("Working...");
    let msg;
    try {
      msg = await invoke(command);
    } catch (e) {
      msg = `Failed: ${e}`;
    }
    setBusy(false);
    if (disposed) return;
    setDisplayMsg(msg);
    clearTimeout(timer);
    timer = setTimeout(() => setDisplayMsg(""), 5000);
  }
  onCleanup(() => {
    disposed = true;
    clearTimeout(timer);
  });

  return (
    <div>
      {displayMsg() == "" ? null : (
        <div class="info-msg">
          <div class="info">
            <div class="info__icon">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="24"
                viewBox="0 0 24 24"
                height="24"
                fill="none"
              >
                <path
                  fill="#393a37"
                  d="m12 1.5c-5.79844 0-10.5 4.70156-10.5 10.5 0 5.7984 4.70156 10.5 10.5 10.5 5.7984 0 10.5-4.7016 10.5-10.5 0-5.79844-4.7016-10.5-10.5-10.5zm.75 15.5625c0 .1031-.0844.1875-.1875.1875h-1.125c-.1031 0-.1875-.0844-.1875-.1875v-6.375c0-.1031.0844-.1875.1875-.1875h1.125c.1031 0 .1875.0844.1875.1875zm-.75-8.0625c-.2944-.00601-.5747-.12718-.7808-.3375-.206-.21032-.3215-.49305-.3215-.7875s.1155-.57718.3215-.7875c.2061-.21032.4864-.33149.7808-.3375.2944.00601.5747.12718.7808.3375.206.21032.3215.49305.3215.7875s-.1155.57718-.3215.7875c-.2061.21032-.4864.33149-.7808.3375z"
                ></path>
              </svg>
            </div>
            <div class="info__title">{displayMsg()}</div>
          </div>
        </div>
      )}
      <div class="optimize ">
        <h1 id="title">Flush DNS Cache</h1>
        <button disabled={busy()} onClick={() => run("optimize")}>Flush DNS</button>
      </div>
      <div class="clean">
        <h1>Clean Temp Files (older than 7 days)</h1>
        <button disabled={busy()} onClick={() => run("clean")}>Clean Up</button>
      </div>
    </div>
  );
}

export default Optimize;
