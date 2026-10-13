import Card from "./cards/qcard";
import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import "./Quarantine.css";
function Quarantine() {
    
    const [quarantine, setQuarantine] = createSignal([[]]);
        
        async function getQuarantine() {
                var quarantine = await invoke("get_quarantine");
                console.log(quarantine);
                //remove element with empty string
                quarantine = quarantine.filter(function (el) {
                        return el != "";
                });
                setQuarantine(quarantine);
        }

        getQuarantine();

        return (
            <div class="quarantine-container">
                <h1 id="title">Files in Quarantine</h1>
                { quarantine().length == 0 ?
                <h2>Nothing to show</h2> 
                : <div class="qcard-container">
                { quarantine().map((item) => (
                        <Card
                                title={item[0]}
                                content={item[1]}
                                filepath={"C:\\neural-av\\Quarantine\\" + item[0] + ".txt"}
                        />
                ))}
        </div>
                }
                

            </div>
        );
}

export default Quarantine;



