import { Show, createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import "./Drivescan.css";

function DriveScan() {
  const [folderlist, setFolderlist] = createSignal([]);
  const [result, setResult] = createSignal([]);
  const [loading, setLoading] = createSignal(false);
  const [message, setMessage] = createSignal("Choose a drive to scan");
  const [dropdown, setDropdown] = createSignal(false);

  var directory = "";

  async function traverse() {
    var folderlist = await invoke("get_drives");
    setFolderlist(folderlist);
  }

  async function multiscan(folder) {
    toggleDropdown();
    setResult([]);
    toggleloader();
    var result = await invoke("remote_inference", { drive: folder });
    setResult(result);
    toggleloader();
    showMsg(`the drive ${folder} has been scanned, found ${result.length} files`);
  }
  function toggleDropdown() {
    setResult([]);
    traverse();
    if (dropdown()) {
      setDropdown(false);
      document.getElementsByClassName("drive-dropdown")[0].style.display =
        "none";
    } else {
      setDropdown(true);
      document.getElementsByClassName("drive-dropdown")[0].style.display =
        "block";
    }
  }

  function toggleloader() {
    if (loading()) {
      document.getElementsByClassName("loader")[0].style.display = "none";
      setLoading(false);
    } else {
      document.getElementsByClassName("loader")[0].style.display = "block";
      setLoading(true);
    }
  }

  function showMsg(msg) {
    setMessage(msg);
    setTimeout(function () {
      setMessage("select a drive to scan");
    }, 5000);
  }

  async function deleteFile(fullpath) {
    var output = await invoke("remote_delete", { filepath: fullpath });
    showMsg(output);
    var newresult = result().filter(function (el) {
      return el[0] != fullpath;
    });
    setResult(newresult);
    
  }
  
  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("folder").click();
  });

  traverse();

  return (
    <div class="drive-container">
      <div class="drive-header">
        <div class="loader" id="loader-container" style="display: none;"></div>
        <button onClick={toggleDropdown} id="folder"> Select Drive </button>
      </div> 
      <div class="drive-dropdown" style="display: none;">
        <ul>
          <li>
           
            <ul>
              {folderlist().map((item) => (
                <li>
                  <button onClick={() => multiscan(item)}>{item}</button>
                </li>
              ))}
            </ul>
          </li>
        </ul>
      </div>

      <div class="result">
        {result().length == 0 ? (
          <p></p>
        ) : (
          <div class="result">
              <div class="multibox-content" id="multibox-content">
              <div class="multibox-content-header">
                {message()}
              </div>
              <div class="multibox-content-body">
                {result().map((file) => (
                  <div
                    class="multibox-content-body-item"
                    id="multibox-content-body-item"
                  >
                    <div class="multibox-text" id="multibox-text">
                      {file[0]} | {file[1]}
                    </div>
                    {file[1] != "Malicious" ? "":
                    <button class="btn-danger" onClick={() => deleteFile(file[0])}>
                      Delete
                    </button>
                    }
                  </div>
                ))}
              </div>
              </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default DriveScan;
