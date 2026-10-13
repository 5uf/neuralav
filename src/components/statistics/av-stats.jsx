import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { useNavigate } from "@solidjs/router";
import "./avstats.css";

export default function Avstats() {
  const navigate = useNavigate();
    const [avList, setAvList] = createSignal([]);

 
    invoke("vt_stats").then((result) => {
        setAvList(result);
    }

    );

      
  return (
    <div class="avstats">
    <div class="avstats-header">
    <h1>List of Antivirus Used</h1> 
      <button class="button2" onClick={() => navigate("/glob")}>Go Back</button>
        </div>
        <div class="avstats-container">
            <div class="avstats-list">
                <ul>
                    {avList().map((av) => (
                        <li>
                            <h5>{av[0]}</h5>
                            <p>{av[1].replace(/['"]+/g, '').toUpperCase()} - {av[6].replace(/['"]+/g, '')}</p>
                        </li>
                    ))}
                </ul>
            </div>
           </div>
    </div>
  );
}
