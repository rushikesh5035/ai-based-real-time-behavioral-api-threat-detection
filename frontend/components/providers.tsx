"use client";

import * as React from "react";
import { TooltipProvider } from "@/components/ui/tooltip";

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <TooltipProvider>{children}</TooltipProvider>
  );
}
