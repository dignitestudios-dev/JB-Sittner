import React, { useContext, useState } from "react";
import { FaChevronUp } from "react-icons/fa";
import { FaAngleDown } from "react-icons/fa6";
import { MyContext } from "../../context/GlobalContext";
import ViewAllModal from "./ViewAllModal";
export default function Attachment() {
  const [openIndex, setOpenIndex] = useState(null);
  const { LookScreen, IsAttachments, setIsViewAll } = useContext(MyContext);
  const handleToggle = (index) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  const attachment = [
    {
      title: "Excel File.xls",
      img: "/xl.webp",
    },
    {
      title: "Document File.pdf",
      img: "/pdf.webp",
    },
    {
      title: "Important Picture.jpg",
      img: "/image.webp",
    },
    {
      title: "Important Video.mp4",
      img: "/video.webp",
    },
  ];

  return (
    <div>
      <div
        id="accordion-collapse"
        data-accordion="collapse"
        className={`${LookScreen ? "w-[40%]" : "w-full"}  mt-2 mx-auto`}
      >
        <div
          type="button"
          className={`flex flex-col items-start justify-between w-full py-4 font-medium rtl:text-right outline-none hover:opacity-95 `}
          data-accordion-target="#accordion-collapse-body-1"
        >
          <button
            name="faq-question"
            type="button"
            className={`flex my-divider pb-2  items-center justify-between w-full  font-medium rtl:text-right  hover:opacity-95  gap-3`}
            onClick={() => !LookScreen && handleToggle(1)}
          >
            <div
              className={`w-auto flex justify-start items-center text-xs md:text-sm lg:text-xl text-left gap-2 `}
            >
              <h2 className={`font-medium text-[13px]`}>Attachments</h2>
            </div>

            {!LookScreen &&
              (openIndex === 1 ? (
                <FaAngleDown className="text-xl" />
              ) : (
                <FaChevronUp className="text-xl" />
              ))}
          </button>

          <div
            id="accordion-1"
            className={`transition-all duration-200 ${
              !openIndex == 1 ? "" : "hidden"
            }`}
          >
            <div className="py-1 rounded-md mt-1 ">
              <ul className="max-w-md  dark:divide-gray-700">
                {[...IsAttachments]?.slice(0, 5)?.reverse()?.map((msg, i) => (
                  <>
                    {msg.images.map((img, index) =>
                      msg.type[index]?.includes("image") ? (
                        <li className="mt-3">
                          <a
                            href={img.url}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <div className="flex items-center space-x-4 rtl:space-x-reverse">
                              <div className="flex-shrink-0 ">
                                <img className="w-10 " src={"/image.webp"} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[13px] font-medium  ">
                                  {img.name}
                                </p>
                              </div>
                            </div>
                          </a>
                        </li>
                      ) : msg.type[index]?.includes("video") ? (
                        <li className="mt-3">
                          <a
                            href={img.url}
                            download
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <div className="flex items-center space-x-4 rtl:space-x-reverse">
                              <div className="flex-shrink-0 ">
                                <img className="w-10 " src={"/video.webp"} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[13px] font-medium  ">
                                  {img.name}
                                </p>
                              </div>
                            </div>
                          </a>
                        </li>
                      ) : msg.type[index]?.includes("spreadsheetml") ? (
                        <li className="mt-3">
                          <a
                            href={img.url}
                            download
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <div className="flex items-center space-x-4 rtl:space-x-reverse">
                              <div className="flex-shrink-0 ">
                                <img className="w-10 " src={"/xl.webp"} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[13px] font-medium  ">
                                  {img.name}
                                </p>
                              </div>
                            </div>
                          </a>
                        </li>


                      ) : (
                        <li className="mt-3">
                          <a
                            href={img.url}
                            download
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            <div className="flex items-center space-x-4 rtl:space-x-reverse">
                              <div className="flex-shrink-0 ">
                                <img className="w-10 " src={"/pdf.webp"} />
                              </div>
                              <div className="flex-1 min-w-0">
                                <p className="text-[13px] font-medium  ">
                                  {img.name}
                                </p>
                              </div>
                            </div>
                          </a>
                        </li>
                      )
                    )}
                  </>
                ))}
                {IsAttachments.length > 4 && (
                  <button
                    onClick={() => setIsViewAll(true)}
                    className="bg-transparent text-[13px] font-medium text-[#007AFF] space-x-4 mt-5 underline"
                  >
                    View all
                  </button>
                )}
              </ul>
            </div>
          </div>
        </div>
        <ViewAllModal />
      </div>
    </div>
  );
}
