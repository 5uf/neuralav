import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import "./memory.css";

function Memory(percent) {
  const [percentage, setPercentage] = createSignal(percent);
  const [color, setColor] = createSignal();

  async function getMemory() {
    const memory = await invoke("memory");
    setPercentage(memory.toFixed(2));
    // set color to gradually change from blue to red
    if (memory < 60) {
      setColor("white");
    } else if (memory < 80) {
      setColor("lightblue");
    } else if (memory < 95) {
      setColor("blue");
    }else{ setColor("red"); }
    document.getElementById("memory-bar").style.display = "block";
  }
 
  getMemory();
  
  setInterval(getMemory, 1000);

  return (
    <div class="memory-container">
      <div class="memory-bar" id="memory-bar">
        <h4 class="memory-title">Memory: {percentage()}%</h4>
        <svg
          class="waves"
          xmlns="http://www.w3.org/2000/svg"
          xmlns:xlink="http://www.w3.org/1999/xlink"
          viewBox="0 24 150 28"
          preserveAspectRatio="none"
          shape-rendering="auto"
        >
          <defs>
            <path
              id="gentle-wave"
              d="M-160 44c30 0 58-18 88-18s 58 18 88 18 58-18 88-18 58 18 88 18 v44h-352z"
            />
          </defs>
          <g class="parallax">
            <use 
              xlink:href="#gentle-wave" 
              x={() => percentage()}
              y="0"
              fill={color()}
            />
            <use 
              xlink:href="#gentle-wave" 
              x={() => percentage()}
              y="3"
              fill={color()}
            />
            <use 
              xlink:href="#gentle-wave" 
              x={() => percentage()}
              y="5"
              fill={color()}
            />
          </g>
        </svg>
      </div>
    </div>
  );
}

export default Memory;
