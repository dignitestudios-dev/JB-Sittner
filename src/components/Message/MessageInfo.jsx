import React, { useContext, useEffect, useState } from "react";
import { MyContext } from "../../context/GlobalContext";
import { IoMdClose } from "react-icons/io";
import { collection, db, onSnapshot, query } from "../../firbase/FirebaseInit";
import moment from "moment";
import 'moment-timezone';
export default function MessageInfo() {
  const { MessageInfo, setIsMessageInfo, msgSeenEmp } = useContext(MyContext);

  function timeAgo(dateString) {
    const momentDate = moment.tz(dateString, "MM/DD/YYYY h:mm A", "America/Denver");

    return momentDate.fromNow();
  }
  
  
  const color = [
    "bg-[#B9FF9E]",
    "bg-[#FFD839]",
    "bg-[#E8F569]",
    "bg-[#94D0E4]",
  ];

  return (
    <>
      {MessageInfo ? (
        <>
          <div className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
            <div className="relative h-[450px]  w-[350px]  my-6 mx-auto max-w-4xl">
              {/*content*/}

              <div className="border-0 px-4 py-4 h-full  rounded-[16px] shadow-lg relative flex flex-col w-full bg-white outline-none focus:outline-none">
                <div className="flex justify-between">
                  <div>
                    <h2 className="text-[18px] font-semibold leading-[21px]">
                      Message Info
                    </h2>
                  </div>
                  <div>
                    <IoMdClose
                      className="cursor-pointer"
                      onClick={() => setIsMessageInfo(false)}
                      size={20}
                    />
                  </div>
                </div>
                {/*body*/}
                <div className="relative h-[90%] mt-4 scroll-box overflow-auto">
                  <div className="py-1 rounded-md  ">
                    <ul className="px-1">
                      {msgSeenEmp
                        .filter((fil) => fil.role != "admin")
                        .map((item, i) => (
                          <li className="mt-3">
                            <div className="flex items-center space-x-2 rtl:space-x-reverse">
                              <div
                                className={`w-[50px] h-[50px]  rounded-full ${color[i]} `}
                              >
                                <img
                                  className="rounded-full w-full  h-full"
                                  src={item.pic ? item.pic : "noprofile.png"}
                                  alt={item.pic}
                                />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[13px] font-medium  ">
                                  {item.name}
                                </p>
                                <p className="text-[#ABABAB] text-[12px]">
                                  {item.seenTime? timeAgo(item.seenTime) : "not seen yet"}
                                </p>
                              </div>
                            </div>
                          </li>
                        ))}
                    </ul>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="opacity-25 fixed inset-0 z-40 bg-black"></div>
        </>
      ) : null}
    </>
  );
}
