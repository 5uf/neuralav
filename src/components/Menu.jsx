import { A } from "@solidjs/router";
import "./Menu.css";

function Menu() {
  const items = [ 
    {name: "Dashboard", icon: "dashboard", url: "/"},
    {name: "Statistics", icon: "statistics", url: "/glob"},
    {name: "Quarantine", icon: "quarantine", url: "/quarantine"},
    {name: "Optimize", icon: "optimize", url: "/optimize"},
    {name: "About System", icon: "about", url: "/about"}
  ]

  return (
    <div class="menu">
      <ul>
        {items.map(item => (
        <A href={item.url}>
          <li>
            <img src={`/icons/${item.icon}.png`} alt={item.name} height={64} width={64} />
            <p>{item.name}</p>
          </li>
          </A>
        ))}
      </ul>
    </div>
   
  );
}

export default Menu;