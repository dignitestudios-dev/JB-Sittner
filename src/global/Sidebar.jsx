import React, { useContext, useEffect, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { admin_links, links } from "../constants/SideBar";
import { IoExitOutline } from "react-icons/io5";
import { MyContext } from "../context/GlobalContext";
import { CiSettings } from "react-icons/ci";
export default function Sidebar({ setIsOpen }) {
  const pathName = useLocation();
  const { setIsLogOut, Employee } = useContext(MyContext);
  const [user, setUser] = useState("");

  useEffect(() => {
    if (Employee?.role == "admin") {
      setUser(true);
    } else if (Employee?.role == "user") {
      setUser(false);
    }
  }, [Employee?.role]);

  return (
    <div className="w-full px-2">
      <div className="flex items-center justify-start mt-[80px] lg:mt-3 mb-3 h-16 ">
        <img src="/whitebglogo.webp" width={120} alt="" srcset="" />
      </div>
      <div className="flex flex-col flex-1 overflow-y-auto">
        <nav className="flex-1  py-4 ">
          {user &&
            admin_links.map((e, i) => (
              <NavLink
                key={i}
                to={e?.to}
                className={`flex text-sm items-center font-normal mt-3 px-4 py-2  ${
                  pathName.pathname == e?.to
                    ? "bg-[#0A8A33] text-white rounded-xl h-[40px]"
                    : "text-[#9F9F9F]"
                } `}
              >
                <span className="text-[20px]">{e.img}</span>
                <span className="ml-2"> {e.title}</span>
              </NavLink>
            ))}
          {!user &&
            links.map((e, i) => (
              <NavLink
                key={i}
                to={e?.to}
                state={{ id: e.title == "Profile" && Employee?.id }}
                className={`flex text-sm items-center font-normal mt-3 px-4 py-2  ${
                  pathName.pathname == e?.to
                    ? "bg-[#0A8A33] text-white rounded-xl h-[40px]"
                    : "text-[#9F9F9F]"
                } `}
              >
                <span className="">{e.img}</span>
                <span className="ml-2"> {e.title}</span>
              </NavLink>
            ))}
          {Employee?.role == "admin" && (
            <button
              className={`flex text-sm items-center font-normal mt-3 px-4 py-2  text-[#9F9F9F] `}
              onClick={() => {
                setIsOpen(true);
              }}
            >
              <span className="">
                <CiSettings size={20} />
              </span>
              <span className="ml-2">Settings</span>
            </button>
          )}

          <button
            className={`flex text-sm items-center font-normal mt-3 px-4 py-2  text-[#9F9F9F] `}
            onClick={() => {
              setIsLogOut(true);
            }}
          >
            <span className="">
              <IoExitOutline size={20} />
            </span>
            <span className="ml-2">Log Out</span>
          </button>
        </nav>
      </div>
    </div>
  );
}
