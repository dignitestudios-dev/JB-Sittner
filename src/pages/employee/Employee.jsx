import React, { useContext, useEffect } from "react";
import EmployeeList from "../../components/Employee/EmployeeList";
import { NavLink, useNavigate } from "react-router-dom";
import { FaPlus } from "react-icons/fa";
import { MyContext } from "../../context/GlobalContext";

export default function Employee() {
  const {Employee}=useContext(MyContext)
  const navigate=useNavigate("");
  useEffect(()=>{
    if(Employee?.role=="user"){
       navigate("/profile",{ state: { id: Employee?.id } });
    }
   },[Employee])
  return (
    <div class="bg-[#F7F7F7] h-screen px-3 py-3 lg:py-10 lg:px-10 ">
      <div className="flex flex-nowrap items-center justify-between">
        <div>
          <NavLink className="font-semibold text-[24px] md:mb-5 leading-[29px] flex items-center">
            {" "}
            Employee Directory
          </NavLink>
        </div>
        <div>
          <NavLink
            to={"/addmember"}
            className={`flex text-sm w-[180px] md:w-[203px] font-semibold text-center bg-[#0A8A33] text-white h-[44px] flex items-center justify-center rounded-[8px] font-semibold md:px-4 mx-5 py-2 `}
          >
            {" "}
            <FaPlus className="mr-2 text-sm" /> Add a Member
          </NavLink>
        </div>
      </div>
      <EmployeeList />
    </div>
  );
}
