import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import Memory from "./widgets/memory";
import Security from "./widgets/security";
import { jsPDF } from "jspdf";
import { useNavigate } from "@solidjs/router";
import "./Dashboard.css";
function Dashboard() {
  const navigate = useNavigate();
  var [displayMsg, setDisplayMsg] = createSignal("");
  var [displayMsg2, setDisplayMsg2] = createSignal("");

  var filepath = "";
  var metadata = "";
  var mal_class = "";
  var accuracy = "";
  var text = "";
  async function scan() {
    filepath = this.files[0].name;
    if (this.files.name != "") {
      showLoading();
      var output = await invoke("identify", { filename: filepath });
      setDisplayMsg(output);
      hideLoading();
      if (output == "Malicious") {
        document.getElementById("loader").style.display = "block";
        var result = await invoke("classify", { filename: filepath });
        metadata = await invoke("metafunc", { filepath: filepath });
        console.log(metadata);
        mal_class = result.split(",")[0];
        accuracy = result.split(",")[1];
        text = result.split(",")[2];
        var classification = mal_class + " (" + accuracy + "%)";
        document.getElementById("loader").style.display = "none";
        var cls = document.getElementById("classification");
        cls.style.whiteSpace = "pre-line";
        cls.textContent = classification + "\n" + text;
        document.getElementById("btn").style.display = "block";
      } else if (output == "Harmless") {
        document.getElementById("classification").textContent = "Harmless";
        document.getElementById("btn").style.display = "none";
      } else {
        document.getElementById("classification").textContent = "";
        document.getElementById("btn").style.display = "none";
      }
    } else {
      setDisplayMsg("No file selected");
    }
  }
  async function deleteFile() {
    showLoading();
    var output = await invoke("delete_file", { filepath: filepath });
    setDisplayMsg2(output);
    hideLoading();
    document.getElementById("output").style.display = "none";
    setTimeout(function () {
      setDisplayMsg2("");
    }, 5000);
    report();
    close();
  }

  async function quarantineFile() {
    showLoading();
    console.log(filepath);
    var output = await invoke("quarantine", {
      file: filepath,
      classification: mal_class,
    });
    console.log(output);
    setDisplayMsg2(output);
    hideLoading();
    document.getElementById("output").style.display = "none";
    setTimeout(function () {
      setDisplayMsg2("");
    }, 5000);
    report();
  }


  async function report() {
    document.getElementById("report").style.display = "block";
    document.getElementById("output").style.display = "none";
  }

 async function sendReport() {
    //get the file name and the classification
    var filename = filepath.split("\\").pop();
    var report = {
      filename: filename,
      classification: mal_class,
      accuracy: accuracy,
    }
    //generate the pdf
    var doc = new jsPDF();
    doc.setFontSize(20);
    doc.text("Neural-AV Report", 10, 10);
    doc.setFontSize(12);
    doc.text("Time Detected: " + new Date().toLocaleString(), 10, 15);
    doc.text("Name of File: " + report.filename, 10, 20);
    doc.text("Path of File: " + filepath, 10, 25);
    doc.text("Malware Classification Type: " + report.classification, 10, 30);
    doc.text("NeuralAV Accuracy: " + report.accuracy, 10, 40);
    doc.text(metadata, 10, 45);
    doc.save("report.pdf");
    
    closeReport();
    setDisplayMsg2("Report sent successfully!");
    setInterval(function () {
      setDisplayMsg2("");
    }
    , 5000);
    close();    
  }

  function closeReport() {
    document.getElementById("report").style.display = "none";
    close();
  }

  function showLoading() {
    document.getElementById("loading").style.display = "block";
    document.getElementById("output").style.display = "none";
    document.getElementById("widget").style.display = "none";
    document.getElementById("dashboard-btn").style.display = "none";
  }

  function hideLoading() {
    document.getElementById("loading").style.display = "none";
    document.getElementById("output").style.display = "block";
  }

  function close() {
    document.getElementById("output").style.display = "none";
    document.getElementById("widget").style.display = "flex";
    document.getElementById("dashboard-btn").style.display = "flex";
    document.getElementById("classification").textContent = "Processing...";
    setDisplayMsg("");
  }
  

  return (
    <div class="container">
      <div id="title-card">My Dashboard</div>
      <div class="dashboard" id="widget">
        <div class="card">
          <Memory />
        </div>
        <div class="card">
          <Security />
        </div>
      </div>
      <br />
      <h4 class="messsage" id="displayMsg2">{displayMsg2}</h4>
        
      <div class="output-card" id="output" style="display: none;">
        <button class="close" onClick={close}>
          X
        </button>
        <div class="title-card">

          <div class="result-process"><h4 id="classification">{displayMsg}</h4>
          <div id="loader" class="lds-hourglass" style={{ display: "none" }}></div>
          </div>
          <div class="process-title">
          <p>1. Preprocess binary and tokenize input</p>
          <p>2. Focus on input relationship and calculate the weight</p>
          <p>3. Acquire context from the representations</p>
          <p>4. The preprocessed text is fed through BERT's layer with a softmax activation function</p>
          <p>5. The threat analysis layer outputs a probability distribution over threat classes.</p>
          </div>
        </div>
        
       
        <div class="btn" id="btn" style={{ display: "none" }}>
          <button id="quarantine" onClick={quarantineFile}>
            Quarantine
          </button>
          <button id="delete" onClick={deleteFile}>
            Delete
          </button>
        </div>
      </div>
      <div class="report-card" id="report" style={{ display: "none" }}>
        <h4>Do you want a PDF report regarding this?</h4>
        <div class="report-card-body">
          <button class="btn" onClick={closeReport} id="no">
            No
          </button>
          <button class="btn" onClick={sendReport} id="yes">
            Yes
          </button>
        </div>
      </div>

      <div class="loader" id="loading" style="display: none;"></div>

      <div class="dashboard-btn" id="dashboard-btn">
        <button class="btn2" onClick={() => navigate("/drivescan")}>Drive Scan</button>
        <button class="btn2" onClick={() => navigate("/multiscan")}>Folder Scan</button>
        <input
          type="file"
          id="file"
          name="file"
          onChange={scan}
          style="display:none;"
        />
        <button
          class="btn2"
          onClick={() => document.getElementById("file").click()}
        >
          File Scan
        </button>
      </div>
    </div>
  );
}

export default Dashboard;
