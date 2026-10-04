import { createContext, useContext, useState } from "react";

const ThemeCtx = createContext({ dark: true, toggle() {} });

export function ThemeProvider({ children }) {
  const [dark, setDark] = useState(true);
  return <ThemeCtx.Provider value={{ dark, toggle: () => setDark(d => !d) }}>{children}</ThemeCtx.Provider>;
}
// eslint-disable-next-line react-refresh/only-export-components
export const useTheme = () => useContext(ThemeCtx);
