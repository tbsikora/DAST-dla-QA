import { useState } from "react";
import { Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText
} from "@mui/material";
import AddCircleOutlineIcon from "@mui/icons-material/AddCircleOutline";
import TimelineIcon from "@mui/icons-material/Timeline";
import HistoryIcon from "@mui/icons-material/History";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import NewScan from "./pages/NewScan";
import Running from "./pages/Running";
import History from "./pages/History";
import TestCatalog from "./pages/TestCatalog";

const nav = [
  { to: "/", label: "Nowy skan", icon: <AddCircleOutlineIcon /> },
  { to: "/running", label: "Przebieg", icon: <TimelineIcon /> },
  { to: "/history", label: "Historia", icon: <HistoryIcon /> },
  { to: "/test-catalog", label: "Katalog testów", icon: <MenuBookIcon /> }
];

const drawerWidth = 300;

export default function App() {
  const [logoLoadError, setLogoLoadError] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  return (
    <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: {
            width: drawerWidth,
            boxSizing: "border-box",
            borderRight: "none",
            bgcolor: "#192033",
            color: "#DDE3F0"
          }
        }}
      >
        <Box sx={{ px: 1, pt: 2.5, pb: 0, textAlign: "center" }}>
          {!logoLoadError ? (
            <Box
              component="img"
              src="/logo-tomsec.png"
              alt="TomSec"
              onError={() => setLogoLoadError(true)}
              sx={{
                display: "block",
                width: "100%",
                mx: "auto",
                height: "auto",
                objectFit: "contain"
              }}
            />
          ) : null}
        </Box>

        <List sx={{ px: 2, pt: 0, mt: -0.75 }}>
          {nav.map((n) => {
            const isActive = location.pathname === n.to;
            return (
            <ListItemButton
              key={n.to}
              onClick={() => navigate(n.to)}
              selected={isActive}
              sx={{
                borderRadius: 2,
                mb: 0.5,
                color: "#C7D0E3",
                "&.Mui-selected": { bgcolor: "rgba(45,127,249,0.18)", color: "#FFFFFF" },
                "&.Mui-selected:hover": { bgcolor: "rgba(45,127,249,0.24)" }
              }}
            >
              <ListItemIcon sx={{ color: "inherit", minWidth: 36 }}>{n.icon}</ListItemIcon>
              <ListItemText primary={n.label} primaryTypographyProps={{ fontSize: 14, fontWeight: 600 }} />
            </ListItemButton>
          )})}
        </List>

        <Box sx={{ mt: "auto", px: 3, pb: 3, color: "#9AA3BD", fontSize: 12 }} />
      </Drawer>

      <Box sx={{ flexGrow: 1 }}>
        <Box sx={{ px: 3, pb: 4, pt: 3 }}>
          <Page>
            <Routes>
              <Route path="/" element={<NewScan />} />
              <Route path="/running" element={<Running />} />
              <Route path="/history" element={<History />} />
              <Route path="/test-catalog" element={<TestCatalog />} />
            </Routes>
          </Page>
        </Box>
      </Box>
    </Box>
  );
}

function Page({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2 }}
    >
      {children}
    </motion.div>
  );
}
