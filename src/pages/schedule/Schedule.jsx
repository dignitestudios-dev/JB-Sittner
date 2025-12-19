import React from "react";
import { FaPlus } from "react-icons/fa";
import { NavLink } from "react-router-dom";
import MessageList from "../../components/Schedule/MessageList";
import DeleteSchedule from "../../components/Schedule/DeleteSchedule";
export default function Schedule() {
  return (
    <div class="bg-[#F7F7F7] h-[100%] py-3 px-3  lg:py-10 lg:px-10 ">
      <div className="flex flex-nowrap items-center justify-between">
        <div>
          <NavLink className="font-semibold text-[24px]  md:mb-5 leading-[29px] flex items-center">
            {" "}
            Schedule Message
          </NavLink>
        </div>
        <div>
          <NavLink
            to={"/createschedule"}
            state={{collection:"scheduled"}}            
            className={`flex text-sm w-[180px] md:w-[203px] font-semibold text-center bg-[#0A8A33] text-white h-[44px] flex items-center justify-center rounded-[8px] font-semibold md:px-4 mx-5 py-2 `}
          >
            {" "}
            <FaPlus className="mr-2 text-sm" /> Create Message
          </NavLink>
        </div>
      </div>

      <MessageList />
      {/* Modal */}
      <DeleteSchedule />
    </div>
  );
}
