import "./header.css";
import { A } from "@solidjs/router";


function Header() {
  return (
    <header className="header">
      <div class="logo">
        <img src="logo.png" alt="logo" height={64} width={64} />
        <h1>NeuralAV</h1>
      </div>
  
      <div class="notification">
      <A href="/notification">
          <img src="icons/notification.png" alt="notification" height={64} width={64} />
        </A>
      </div>
    </header>

  );
}

export default Header;