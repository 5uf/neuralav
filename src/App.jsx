import Menu from "./components/Menu";
import Optimize from "./components/Optimize";
import Settings from "./components/Settings";
import Dashboard from "./components/Dashboard";
import Quarantine from "./components/Quarantine";
import Notification from "./components/Notification";
import MultiBox from "./components/multiscan/MultiBox";
import DriveScan from "./components/drivescan/Drivescan";
import About from "./components/about/About";
import Header from "./partials/header";
import Footer from "./partials/footer";
import { Route } from "@solidjs/router";
import "./App.css";

export function Layout(props) {
  return (
    <>
    <Header />
    <div class="container">
      <Menu />
      {props.children}
      <Footer />
    </div>
    </>
  );
}

export const routes = (
  <>
    <Route path="/" component={Dashboard} />
    <Route path="/multiscan" component={MultiBox} />
    <Route path="/drivescan" component={DriveScan} />
    <Route path="/optimize" component={Optimize} />
    <Route path="/settings" component={Settings} />
    <Route path="/quarantine" component={Quarantine} />
    <Route path="/notification" component={Notification} />
    <Route path="/about" component={About} />
    <Route path="*" component={Dashboard} />
  </>
);
