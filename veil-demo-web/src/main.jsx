import React from "react";
import { createRoot } from "react-dom/client";
import VeilDemo from "./VeilDemo.jsx";

const root = document.getElementById("root");
createRoot(root).render(
  <React.StrictMode>
    <VeilDemo />
  </React.StrictMode>
);
