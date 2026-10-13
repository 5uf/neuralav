import "./About.css";
import { createSignal } from "solid-js";

function About() {
  const [displayMsg, setDisplayMsg] = createSignal(false);

  function showMalware() {
    if (displayMsg()) {
      setDisplayMsg(false);
      document.getElementById("malware").style.display = "none";
      document.getElementById("about").style.display = "flex";
    } else {
      setDisplayMsg(true);
      document.getElementById("malware").style.display = "flex";
      document.getElementById("about").style.display = "none";
    }
  }



  return (
    <div class="about-container">
      <div class="about-card" id="about" style={{ display: "flex" }}>
        <div class="about-card-header">
          <h1>About Neural-AV's BERT Neural network engine</h1>
        </div>
        <div class="about-card-body">
          <p>
            Neural-AV is an antimalware software that aims to use neural networks to detect
            next generation malwares which using artificial intelligence to
            evade detection and stealthly carry out their malicious activities.
          </p>
          <p>
            The engine called BERT (Bidirectional Encoder
            Representations from Transformers) which is a neural network for
            natural language processing (NLP) pre-training developed by Google.
            The model is fine-tuned using a dataset of Unicode-encoded
            hexadecimal representation of both AI-powered malwares and normal
            malwares.
          </p>
          <p>
            1. Preprocessing: Split the input text into
            individual words or subwords. Assign each token a
            numerical vector representing its meaning. Inject markers indicating word order for context understanding. </p>
          <p>2.
            Transformer Encoder Loop: Divide into
            multiple "heads" focusing on different word relationships. Each
            head calculates weighted interactions between words, enriching their
            representations. Apply non-linear
            transformations for deeper feature extraction. Stabilize learning and improve
            information flow. Focus on word relationship, calculate the weight,
            enhance representation, Applying non-linear transformations for deeper
            feature extraction. Stabilize learning and improve information flow
            </p>
          <p>3. Contextualized Word Representations: Each word emerges with a
            rich embedding, capturing its meaning based on surrounding words and
            overall sentence structure. acquire context from the representations
            </p>
          <p>4. Task-Specific Fine-Tuning: Add additional layers specialized for
            the desired task (e.g., sentiment analysis, question answering).
            These layers leverage the pre-trained knowledge from BERT but learn
            task-specific features. </p>
          <p>5. Inference Forward Pass: Feed the
            preprocessed text through the pre-trained BERT and task-specific
            layers. No backpropagation or weight updates occur, utilizing the
            already learned knowledge. </p>
          <p>6. Probability Output: The final layer
            generates probability values for different possible outcomes (e.g.,
            sentiment category, answer choice).
          </p>
        </div>
        <button class="button" onClick={showMalware}>
          Learn about BlackMamba
        </button>
      </div>
      <div class="about-malware" id="malware" style={{ display: "none" }}>
        <div class="about-card-header">
          <h1>About Malware</h1>
          <p>
            BlackMamba malware utilizes a large language model (LLM) to
            synthesize polymorphic keylogger functionality on-the-fly by
            dynamically modifying the benign code at runtime. This is achieved
            without the need for any command-and-control infrastructure to
            deliver or verify the malicious keylogger functionality. The
            technique can runs completely undetected by EDR intervention. The
            neural network code synthesis, specifically using a
            transformer-based LLM like ChatGPT, allows BlackMamba to generate
            new code based on a prompt or input code, enabling the polymorphism
            magic within the malware.
          </p>
          <div class="about-card-body">
          <p>
            1. BlackMamba contacts the OpemAI using API requests to generate malicious payload and returns the payload in the form of code
          </p>
          <p>
            2. The malware then executes the code and the keylogger is activated
          </p>
          <p>
            3. The keylogger then records the keystrokes and sends it to the
            attacker through the trusted channel such as Microsoft Teams
          </p>
          </div>
        </div><button class="button" onClick={showMalware}>
          Go Back
        </button>
      </div>
      
    </div>
  );
}

export default About;
