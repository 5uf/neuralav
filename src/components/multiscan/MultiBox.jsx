import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import "./MultiBox.css";

function MultiBox() {
  const [filelist, setFilelist] = createSignal([[]]);
  const [loading, setLoading] = createSignal(false);
  const [message, setMessage] = createSignal("select a folder to scan");

  var directory = "";
  document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("folder").click();
  });

  async function deleteFile(fullpath) {
    var output = await invoke("remote_delete", { filepath: fullpath });
    showMsg(output);
    var newfilelist = filelist().filter(function (el) {
      return el[0] != fullpath;
    });
    setFilelist(newfilelist);
  }

  async function quarantineFile(fullpath, classification) {
    var output = await invoke("quarantine_file", { filepath: fullpath , classification: classification});
    showMsg(output);
    var newfilelist = filelist().filter(function (el) {
      return el[0] != fullpath;
    });
    setFilelist(newfilelist);
  }
  

  function toggleLoader() {
    if (loading()) {
      setLoading(false);
      document.getElementById("loader").style.display = "none";
    } else {
      setLoading(true);
      document.getElementById("loader").style.display = "block";
    }
  }

  function showMsg(msg) {
    setMessage(msg);
    setTimeout(function () {
      setMessage("select another folder to scan");
    }, 5000);
  }

  async function multiscan() {
    setFilelist([[]]);
    directory = this.files[0].webkitRelativePath.split("/")[0];
    if (directory != "") {
      toggleLoader();
      console.log(directory);
      var filelist = await invoke("multiscan", { directory: directory });
      setFilelist(filelist);
      toggleLoader();
      showMsg(
        `the folder ${directory} has been scanned, found ${filelist.length} files`
      );
    } else {
      setMessage("No folder selected");
    }
    
  }

  return (
    <div class="multibox-container">
      <div class="loader-container" id="loader" style={{ display: "none" }}>
        <div class="loader"></div>
        <h4>Scanning...</h4>
      </div>
      <br />
      <label for="folder" id="message">
        {message()}
      </label>
      <input
        type="file"
        id="folder"
        name="folder"
        webkitdirectory=""
        directory=""
        onchange={multiscan}
      />
      {filelist() == "" ? (
        <div class="text-before-scan">
          <h4>Scan a folder to see the results</h4>
        </div>
      ) : (
        <div class="multibox-content" id="multibox-content">
          <div class="multibox-content-body">
            {filelist().map((file) => (
              <div
                class="multibox-content-body-item"
                id="multibox-content-body-item"
              >
                <div class="multibox-text" id="multibox-text">
                  {file[0]} | {file[1]}-{file[2].split(",")[0]}
                </div>
               { file[1] == "Malicious" ? (
                <>
                   <button class="btn-danger" onClick={() => deleteFile(file[0])}>
                  Delete
                </button>
                <button class="btn-success" onClick={() => quarantineFile(file[0], file[2].split(",")[0])}>
                  Quarantine
                </button>
                </>
                ) : (
                  <h2></h2>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default MultiBox;
