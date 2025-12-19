import React, { useContext, useEffect, useRef, useState } from "react";
import Dropdown from "../components/Navbar/Dropdown";
import { MyContext } from "../context/GlobalContext";
import { NavLink } from "react-router-dom";


export default function Navbar() {
  const {Employee } = useContext(MyContext);
  const DropdownRef = useRef(null);
  const toggleModal = () => {
    setIsDropdown(!IsDropdownOpen);
  };


  return (
    <div class="flex items-center justify-between h-16 bg-white  border-b border-gray-200">
      <div className="flex items-center w-full justify-end pr-4">
        {Employee?.role == "user" && (
          <div className="flex justify-end">
            <Dropdown />
          </div>
        )}
        {Employee?.role == "user" ? (
          <NavLink to={"/profile"} state={{id:Employee.id}} className="flex items-center">
           <img
              src={Employee?.role == "user"&&Employee.pic?Employee?.pic:"/noprofile.png"}
              className="rounded-full cursor-pointer w-[40px] h-[40px] object-cover"
              alt=""
            />
            <div>
              <h2 className="font-medium ml-2 text-[13px] leading-[15px]">
                {" "}
                {Employee?.name}
                <br />
                <span className="text-[#9E9E9E]">
                  {Employee?.role == "admin" ? "Admin" : "Employee"}
                </span>
              </h2>
            </div>
          </NavLink>
        ) : (
          <button className="flex items-center">
            <img
              src={Employee?.role == "admin"&&Employee?.pic?Employee?.pic:"/noprofile.png"}
              className="rounded-full cursor-pointer w-[40px] h-[40px] object-cover"
              alt=""
            />
            <div>
              <h2 className="font-medium ml-2 text-[14px] leading-[15px]">
                {" "}
                {Employee?.name}
                <br />
                <span className="text-[#9E9E9E] text-[12px]">
                  {Employee?.role == "admin" ? "Admin" : "Employee"}
                </span>
              </h2>
            </div>
          </button>
        )}
      </div>
    </div>
  );
}
