import { createSignal, createMemo, createEffect } from 'solid-js';
import "./Settings.css"

function Settings() {

  //change theme color
  const [theme, setTheme] = createSignal('light');
  const [themeColor, setThemeColor] = createSignal('blue');

  createEffect(() => {
    if (theme() === 'dark') {
      document.body.classList.add('dark');
    } else {
      document.body.classList.remove('dark');
    }
  }
  );

  createEffect(() => {
    if (themeColor() === 'blue') {
      document.body.classList.add('blue');
      document.body.classList.remove('red');
      document.body.classList.remove('green');
    } else if (themeColor() === 'red') {
      document.body.classList.add('red');
      document.body.classList.remove('blue');
      document.body.classList.remove('green');
    } else {
      document.body.classList.add('green');
      document.body.classList.remove('red');
      document.body.classList.remove('blue');
    }
  }

  );

  

  return (
    <div class="settings">
      <div class="setting">
        <h3>Theme</h3>
        <div class="theme">
          <div class="theme-option">
            <input type="radio" id="light" name="theme" value="light" checked={theme() === 'light'} onChange={() => setTheme('light')} />
            <label for="light">Light</label>
          </div>
          <div class="theme-option">
            <input type="radio" id="dark" name="theme" value="dark" checked={theme() === 'dark'} onChange={() => setTheme('dark')} />
            <label for="dark">Dark</label>
          </div>
        </div>
      </div>
      <div class="setting">
        <h3>Theme Color</h3>
        <div class="theme">
          <div class="theme-option">
            <input type="radio" id="blue" name="theme-color" value="blue" checked={themeColor() === 'blue'} onChange={() => setThemeColor('blue')} />
            <label for="blue">Blue</label>
          </div>
          <div class="theme-option">
            <input type="radio" id="red" name="theme-color" value="red" checked={themeColor() === 'red'} onChange={() => setThemeColor('red')} />
            <label for="red">Red</label>
          </div>
          <div class="theme-option">
            <input type="radio" id="green" name="theme-color" value="green" checked={themeColor() === 'green'} onChange={() => setThemeColor('green')} />
            <label for="green">Green</label>
          </div>
        </div>
      </div>
    </div>
  );

}

export default Settings;

