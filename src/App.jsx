import { ToastContainer } from "react-toastify";
import "./App.css";
import { MyContextProvider } from "./context/GlobalContext";
import AppRoutes from "./routes/AppRoutes";
function App() {
  if (typeof global === 'undefined') {
    var global = window;
  }
  return (
    <>
      <ToastContainer />
      <MyContextProvider>
        <AppRoutes />
      </MyContextProvider>
    </>
  );
}

export default App;
