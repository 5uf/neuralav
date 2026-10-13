import { createSignal } from 'solid-js';
import { invoke } from "@tauri-apps/api/core";
import "./security.css";

function Security() {

const [percentage, setPercentage] = createSignal();

async function getSecurity() {
    const security = await invoke("security");
    setPercentage(security.toFixed(2));
}
getSecurity();
//return a chart of security
return (
    <div class="security-container">
	<div class="card">
		<div class="text">
			<span>Security</span>
			<p class="subtitle">{percentage()}%</p>
		</div>
	</div>
    </div>
);

}

export default Security;
