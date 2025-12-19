import React, { useContext } from "react";
import { MyContext } from "../../context/GlobalContext";
import { IoMdClose } from "react-icons/io";
export default function AddMemberModal() {
  const { AddMem, setIsAddMem } = useContext(MyContext);

  const user = [
    {
      title: "Adam Gilchrist",
      img: "/large-person-4.png",
      status: "pending",
    },
    {
      title: "Mike Tyson",
      img: "/large-person-3.png",
      status: "pending",
    },
    {
      title: "Adam Gilchrist",
      img: "/large-person-4.png",
      status: "pending",
    },
    {
      title: "Mike Tyson",
      img: "/large-person-3.png",
      status: "pending",
    },
    {
      title: "Andrew Garfield",
      img: "/large-person-2.png",
      status: "added",
    },
    {
      title: "John Cena",
      img: "/large-person-1.png",
      status: "added",
    },

    {
      title: "Andrew Garfield",
      img: "/large-person-2.png",
      status: "added",
    },
    {
      title: "John Cena",
      img: "/large-person-1.png",
      status: "added",
    },
  ];
  const color = [
    "bg-[#B9FF9E]",
    "bg-[#FFD839]",
    "bg-[#E8F569]",
    "bg-[#94D0E4]",
  ];

  return (
    <>
      {AddMem ? (
        <>
          <div className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
            <div className="relative h-[400px]  w-[350px]  my-6 mx-auto max-w-4xl">
              {/*content*/}
              <div className="border-0 px-4 py-4 h-full  rounded-lg shadow-lg relative flex flex-col w-full bg-white outline-none focus:outline-none">
                <div className="flex justify-between">
                  <div>
                    <h2 className="text-[18px] font-semibold leading-[21px]">
                      Members
                    </h2>
                  </div>
                  <div>
                    <IoMdClose
                      className="cursor-pointer"
                      onClick={() => setIsAddMem(false)}
                      size={20}
                    />
                  </div>
                </div>
                {/*body*/}
                <div className="relative h-[90%] mt-4 scroll-box overflow-auto">
                  <div className="py-1 rounded-md  ">
                    <ul className="px-2">
                      {user.map((item, i) => (
                        <li className="mt-3 flex justify-between items-center">
                          <div className="flex items-center space-x-4 rtl:space-x-reverse">
                            <div
                              className={`w-[50px] h-[50px]  rounded-full ${color[i]} `}
                            >
                              <img
                                className="object-contain w-full  h-full"
                                src={item.img}
                                alt={item.img}
                              />
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-[13px] font-medium  ">
                                {item.title}
                              </p>
                            </div>
                          </div>
                          <div>
                            <button
                              className={` ${
                                item.status == "pending"
                                  ? "bg-[#0A8A33] text-white"
                                  : "bg-[#0A8A331A] text-[#0A8A33]"
                              }   rounded-lg  w-[96px] h-[32px]   text-[13px] font-normal text-nowrap text-center`}
                            >
                              {item.status == "pending"
                                ? "Add Member"
                                : "Added"}
                            </button>
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
