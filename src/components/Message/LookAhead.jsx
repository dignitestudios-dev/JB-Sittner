import React, { useContext, useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { FaPlus } from "react-icons/fa6";
import { MyContext } from "../../context/GlobalContext";

export default function LookAhead({ pendingNotifications }) {
  const { Employee } = useContext(MyContext);

  return (
    <div className=" mt-3 h-[100%] scroll-box py-3 px-3 overflow-y-scroll">
      {Employee?.role == "admin" && (
        <NavLink
          to={"/createschedule"}
          state={{ collection: "look" }}
          className={`flex text-sm w-[203px] font-semibold text-center bg-[#0A8A33] text-white h-[44px] items-center justify-center rounded-[8px] mt-3 px-4 mx-5 py-2 `}
        >
          {" "}
          <FaPlus className="mr-2 text-sm" /> Create New Message
        </NavLink>
      )}
      {pendingNotifications && pendingNotifications?.length > 0 ? (
        pendingNotifications
          ?.sort((a, b) => a.createdAt.toDate() - b.createdAt.toDate()) // Sorting the notifications based on creation time
          ?.sort(
            (a, b) => new Date(a.date).getTime() - new Date(b.date).getTime()
          ) // Sort by date, soonest first
          ?.map((item, i) => (
            <div key={i} className="look-ahead px-3 py-3 w-[100%]">
              <div className="username mb-3 flex items-center justify-between">
                <h2 className="font-semibold text-sm leading-[14px]">
                  {new Date(item.date).toLocaleDateString("en-US", {
                    weekday: "long",
                    timeZone: "America/Denver", // Specify Mountain Time zone here
                  })}
                </h2>
                {Employee?.role === "admin" && (
                  <NavLink
                    to={"/editschedule"}
                    state={{ data: item, collection: "look" }}
                    className="bg-transparent"
                  >
                    <img src="/whiteedit.png" className="w-5" alt="Edit" />
                  </NavLink>
                )}
              </div>
              <div className="w-full py-2 px-2 bg-[#F9F9F9] border border-[#DFDFDF] rounded-[10px]">
                <div  className={`flex items-end ${item.images.length > 5 && 'flex-wrap' }  justify-between`}>
                  <div className={` ${item.images.length > 5 && 'flex items-center mb-2 justify-between w-full' } `}>
                    <div className="w-full rounded-2xl mt-2 text-xs font-normal">
                      {item.message}
                    </div>
                    <div>
                    <span className="text-[12px] font-normal text-[#5C5C5C]">
                      {item.date}
                    </span>
                    <span className="text-[12px] ml-2 font-normal text-[#5C5C5C]">
                      {item.time}
                    </span>
                    </div>
                  </div>
                  <div>
                    {item.images.length > 0 && (
                      <div className={`flex flex-wrap items-center  gap-4`}>
                        {item.images.map((img, index) =>
                          item.type[index]?.includes("image") ? (
                            <div
                              key={index}
                              className="rounded-xl w-[100px] flex justify-center py-1 bg-[#F4F4F4] text-xs font-normal"
                            >
                              <a
                                href={img.url}
                                download
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                <img
                                  src={img.url ? img.url : "/noprofile.png"}
                                  className="cursor-pointer rounded-md h-[30px] w-[30px]"
                                  alt=""
                                />
                              </a>
                            </div>
                          ) : item.type[index]?.includes("video") ? (
                            <div
                              key={index}
                              className="rounded-xl w-[100px] flex justify-center bg-[#F4F4F4] text-xs font-normal"
                            >
                              <a
                              href={img.url}
                              download
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                           <img
                                src="/video.webp"
                                alt=""
                                className="h-[50px] rounded-md w-[50px]"
                              />
                              </a>
                            </div>
                          ) : item.type[index]?.includes("spreadsheetml") ? (
                            <div
                              key={index}
                              className="rounded-xl w-[100px] flex justify-center py-1 bg-[#F4F4F4] text-xs font-normal"
                            >
                              <a
                                href={img.url}
                                download
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                <img
                                  src="/xl.png"
                                  className="cursor-pointer"
                                  alt=""
                                />
                              </a>
                            </div>
                          ) : (
                            <div
                              key={index}
                              className="rounded-xl w-[100px] flex justify-center py-1 bg-[#F4F4F4] text-xs font-normal"
                            >
                              <a
                                href={img.url}
                                download
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                <img
                                  src="/pdf.png"
                                  className="cursor-pointer h-[50px] rounded-md w-[50px]"
                                  alt=""
                                />
                              </a>
                            </div>
                          )
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))
      ) : (
        <div className="no-data-message text-center py-5">
          <p className="text-sm text-gray-500">No Look Ahead available.</p>
        </div>
      )}
    </div>
  );
}
