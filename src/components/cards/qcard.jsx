import "./qcard.css";
import { createSignal } from 'solid-js';
import { invoke } from "@tauri-apps/api/core";

const props = {
    title: String,
    content: String,
    filepath: String,
}

function Card(props) {

    const [displayMsg, setDisplayMsg] = createSignal("");

    async function restore() {
        let result = await invoke("restore", { filename: props.title});
        setDisplayMsg(result);
        document.getElementsByClassName("card2")[0].style.display = "none";
        document.getElementsByClassName("msg")[0].style.display = "block";
        setTimeout(function(){ 
            document.getElementsByClassName("msg")[0].style.display = "none";
            document.getElementsByClassName("card2")[0].style.display = "block";
        }, 1000);
        window.location.reload();
    }

    async function deleteFile() {
        let q_filepath = "C:\\neural-av\\Quarantine\\" + props.title + ".txt";
        console.log(q_filepath);
        let result2= await invoke("delete_q", { filepath: q_filepath});
        setDisplayMsg(result2);
        document.getElementsByClassName("card2")[0].style.display = "none";
        document.getElementsByClassName("msg")[0].style.display = "block";
        setTimeout(function(){ 
            document.getElementsByClassName("msg")[0].style.display = "none";
            document.getElementsByClassName("card2")[0].style.display = "block";
            window.location.reload();
        }, 1000);
        window.location.reload();
    }

    // swap content with message
    return (
        <>
    <div class="msg">
        {displayMsg()}
        </div>
        <div class="card2"> 
            <div class="header">
                <h2>{props.title}</h2>
            </div>
            <div class="body">
                <p>{props.content} is detected found at {props.filepath}</p>
            </div>
            
            <div class="footer">
                <button class="card2-button" id="restore2" onClick={restore}>Restore</button>
                <button class="card2-button" id="delete2" onClick={deleteFile}>Delete</button>
            </div>
        </div></>
    );




}

export default Card;