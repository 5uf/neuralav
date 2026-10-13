import "./Notification.css";
import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";

function Notification() {
  const [notification, setNotification] = createSignal([[]]);

  async function getNotification() {
    var notification = await invoke("get_noti");
    setNotification(notification);
  }

  getNotification();

  return (
    <div class="noti-container"> 
    <h1 id="title" >Files in Quarantine</h1>
      {notification() == [[]] ? (
        <h2>Nothing to show</h2>
      ) : (
        <div class="notification-content">
         
          {notification().map((item) => (
            <h3>
              {item[0]},{item[1]},{item[2]},{item[3]}{" "}
            </h3>
          ))}
        </div>
      )}
    </div>
  );
}

export default Notification;
