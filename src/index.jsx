/* @refresh reload */
import { render } from "solid-js/web";
import { Router } from "@solidjs/router";
import "@fontsource/ibm-plex-sans/latin-400.css";
import "@fontsource/ibm-plex-sans/latin-500.css";
import "@fontsource/ibm-plex-sans/latin-600.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "@fontsource/ibm-plex-mono/latin-600.css";
import { Layout, routes } from "./App";

render(
    () => <Router root={Layout}>{routes}</Router>,
    document.getElementById("root")
);
