import { useContext, useEffect, useRef, useState } from "react";
import { HiOutlineMenuAlt2 } from "react-icons/hi";
import Sidebar from "./Sidebar";
import Navbar from "./Navbar";
import LogOut from "../components/Logout/LogOut";
import { MyContext } from "../context/GlobalContext";
import DropdownList from "../components/Navbar/DropdownList";
import { useNavigate } from "react-router-dom";
import Cookies from "js-cookie";
import {
  auth,
  onAuthStateChanged,
  collection,
  db,
  getDocs,
  query,
  where,
  onSnapshot,
} from "../firbase/FirebaseInit";
import SettingModal from "./SettingModal";

const Layout = ({ pages }) => {
  const sidebarRef = useRef(null);
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const { setEmployee, setLoader } = useContext(MyContext);
  const cookieData = Cookies.get("employe");
  const [settingModal, setSettingModal] = useState(false);
  const toggleModal = () => setIsOpen((prev) => !prev);

  useEffect(() => {
    // Set initial cookies state
    Cookies.set("first", false);

    const fetchData = async () => {
      if (cookieData) {
        try {
          const data = cookieData && JSON.parse(cookieData);

          if (data.email) {
            setEmployee(data);
            getEmployee(data.email); // Fetch employee details
          } else {
            clearEmployeeAndNavigate();
          }
        } catch (error) {
          console.error("Error parsing cookie data:", error);
          clearEmployeeAndNavigate();
        }
      } else {
        clearEmployeeAndNavigate();
      }
    };

    fetchData();

    // Cleanup function (unsubscribe from Firebase on component unmount)
    return () => {
      setLoader(false); // Ensures loader is off if component unmounts
    };
  }, [cookieData, setEmployee]);

  const clearEmployeeAndNavigate = () => {
    const data = cookieData && JSON.parse(cookieData);

    if (!data) {
      Cookies.remove("employe");
      setEmployee({});
      navigate("/login");
    }
    if (data?.role == "user") {
      Cookies.remove("employe");
      setEmployee({});
      navigate("/login");
    }
    console.log(data, "testing data");
  };

  const getEmployee = (userEmail) => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(employeesRef);
    const unsubscribe = onSnapshot(
      employeeQuery,
      (querySnapshot) => {
        const employeeData = querySnapshot.docs.map((doc) => ({
          docId: doc.id,
          ...doc.data(),
        }));

        const currentUser = employeeData.find((emp) => emp.email === userEmail);

        if (!currentUser) {
          Cookies.set("employe", "");
          clearEmployeeAndNavigate();
        }
      },
      (error) => {
        console.error("Error fetching employees: ", error);
        clearEmployeeAndNavigate();
      }
    );

    return () => unsubscribe();
  };
  return (
    <div className="w-screen h-screen flex justify-start items-start overflow-hidden">
      <div
        onClick={toggleModal}
        className={`w-screen h-screen fixed top-0 left-0 transition-all duration-500  ${
          isOpen ? " lg:translate-x-0" : "-translate-x-full lg:translate-x-0"
        } lg:static  z-[2000] lg:z-auto px-3 lg:w-60 xl:w-72 flex flex-col gap-3 items-center justify-start py-0 lg:h-full `}
      >
        <div
          ref={sidebarRef}
          className={`fixed top-0 left-0 transition-all duration-200  ${
            isOpen ? " lg:translate-x-0" : "-translate-x-full lg:translate-x-0"
          } lg:static w-[60%] z-[2000] lg:z-auto lg:w-60 xl:w-72 flex flex-col gap-3 items-center justify-start py-0 h-full bg-[#181818]`}
        >
          <Sidebar isOpen={settingModal} setIsOpen={setSettingModal} />
        </div>
      </div>

      <div className="w-full relative lg:w-[calc(100%-15rem)] xl:w-[calc(100%-18rem)]   overflow-y-auto overflow-x-hidden">
        <div className="sticky  h-16 bg-white flex items-center justify-between lg:justify-end px-4 z-[99]">
          <button
            onClick={() => setIsOpen((prev) => !prev)}
            className="lg:hidden block"
          >
            <HiOutlineMenuAlt2 className="text-2xl" />
          </button>
          <Navbar  />
        </div>
        <div className="">{pages}</div>
        <DropdownList />
        <LogOut />
        <SettingModal isOpen={settingModal} setIsOpen={setSettingModal} />
      </div>
    </div>
  );
};

export default Layout;
