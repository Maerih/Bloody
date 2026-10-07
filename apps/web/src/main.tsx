import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { applyInitialTheme } from "./app/theme";
import "./styles.css";

applyInitialTheme();

const container = document.getElementById("root");
if (!container) throw new Error("Bloody: #root element missing from index.html");

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
