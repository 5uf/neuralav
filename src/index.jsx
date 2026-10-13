/* @refresh reload */
import { render } from "solid-js/web";
import { Router } from "@solidjs/router";
import "./output.css";
import { Layout, routes } from "./App";

render(
    () => <Router root={Layout}>{routes}</Router>,
    document.getElementById("root")
);
