import React, { useEffect, useState } from "react";

export default function LookBehind({ deliveredNotifications }) {
  const [FilterLook,setFilterLook]=useState([])
  useEffect(()=>{
    const twoWeeksAgo = new Date();
    twoWeeksAgo.setDate(twoWeeksAgo.getDate() - 7); // Get the date 14 days ago
    
    const filteredNotifications = deliveredNotifications.filter(item => {
      const itemDate = new Date(item.date);
      return itemDate >= twoWeeksAgo; // Only keep notifications within the last 14 days
    });
    setFilterLook(filteredNotifications)
  },[deliveredNotifications])
  return (
    <div className=" mt-3 h-[100%] scroll-box px-3 py-3 overflow-auto">
      {FilterLook && FilterLook.length > 0 ? (
        FilterLook.map((item, i) => (
          <div className="look-behind  px-3 py-3 w-[100%]" key={i}>
            <div className="username mb-3">
              <h2 className="font-semibold text-sm leading-[14px] ">
                {new Date(item.date).toLocaleDateString("en-US", {
                  weekday: "long",
                })}
              </h2>
            </div>
            <div className="w-full py-2 px-2 bg-[#F9F9F9] border border-[#DFDFDF] rounded-[10px]">
              {/* <h3 className="font-semibold text-sm leading-[14px]">
                Day {new Date(item.date).getDay()}
              </h3> */}
              <div className={`flex items-end ${item.images.length > 5 && 'flex-wrap' }  justify-between`}>
                <div className={` ${item.images.length > 5 && 'flex items-center mb-2 justify-between w-full' } `} >
                  <div className=" w-full rounded-2xl mt-2 text-xs font-normal">
                    {item.message}
                  </div>
                  <div>
                  <span className="text-[12px] font-normal text-[#5C5C5C]">
                    {item.date}
                  </span>
                  <span className="text-[12px] text-nowrap ml-2 font-normal text-[#5C5C5C]">
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
                            className="rounded-xl flex justify-center  py-1 bg-[#F4F4F4] text-xs font-normal"
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
                            className="rounded-xl flex justify-center  bg-[#F4F4F4] text-xs font-normal"
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
                            className="rounded-xl flex justify-center  py-1 bg-[#F4F4F4] text-xs font-normal"
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
                            className="rounded-xl flex justify-center  py-1 bg-[#F4F4F4] text-xs font-normal"
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
          <p className="text-sm text-gray-500">No Look Behind available.</p>
        </div>
      )}
    </div>
  );
}
