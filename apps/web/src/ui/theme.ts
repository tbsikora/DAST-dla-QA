import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "light",
    primary: {
      main: "#2D7FF9",
      dark: "#1E5FD0",
      light: "#7FB2FF"
    },
    secondary: {
      main: "#22C55E"
    },
    background: {
      default: "#F6F8FC",
      paper: "#FFFFFF"
    },
    text: {
      primary: "#1C2333",
      secondary: "#5B6476"
    }
  },
  shape: {
    borderRadius: 16
  },
  typography: {
    fontFamily: '"Manrope", "Segoe UI", "Helvetica Neue", Arial, sans-serif',
    h1: { fontSize: 28, fontWeight: 700 },
    h2: { fontSize: 22, fontWeight: 700 },
    h3: { fontSize: 18, fontWeight: 600 }
  },
  components: {
    MuiPaper: {
      styleOverrides: {
        root: {
          borderRadius: 16
        }
      }
    },
    MuiButton: {
      defaultProps: {
        disableElevation: true,
        variant: "contained"
      },
      styleOverrides: {
        root: {
          borderRadius: 12,
          textTransform: "none",
          fontWeight: 600
        },
        contained: {
          backgroundColor: "#192033",
          color: "#FFFFFF",
          "&:hover": {
            backgroundColor: "#141A2A"
          },
          "&.Mui-disabled": {
            backgroundColor: "#E5E7EB",
            color: "#9CA3AF",
            boxShadow: "none"
          }
        },
        outlined: {
          borderColor: "#192033",
          color: "#FFFFFF",
          backgroundColor: "#192033",
          "&:hover": {
            backgroundColor: "#141A2A",
            borderColor: "#141A2A"
          },
          "&.Mui-disabled": {
            backgroundColor: "#E5E7EB",
            color: "#9CA3AF",
            borderColor: "#E5E7EB",
            boxShadow: "none"
          }
        }
      }
    },
    MuiTextField: {
      defaultProps: {
        variant: "outlined",
        size: "small"
      }
    },
    MuiChip: {
      styleOverrides: {
        root: {
          borderRadius: 999
        }
      }
    }
  }
});
