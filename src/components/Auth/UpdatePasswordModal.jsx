import React, { useContext } from "react";
import { IoMdClose } from "react-icons/io";
import { MyContext } from "../../context/GlobalContext";
import { useLocation, useNavigate } from "react-router-dom";
export default function UpdatePasswordModal() {
  const {PasswordSuccessFullChange,setPasswordSuccessFullChange}=useContext(MyContext);
  const navigate=useNavigate("");
  const loc=useLocation();

  
  
  return (
    <>
    
      {PasswordSuccessFullChange ? (
        <>
          <div
            className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none"
          >
            <div className="relative w-[490px]  my-6 mx-auto max-w-4xl">
              {/*content*/}
              <div className="border-0 h-[339px] rounded-[12px] shadow-lg relative flex flex-col w-full bg-white outline-none focus:outline-none">
                {/*header*/}
                <div className="flex items-start justify-between pr-3 pt-3">
                  <button
                    className="p-1 ml-auto bg-transparent border-0 text-black  float-right text-3xl leading-none font-semibold outline-none focus:outline-none"
                    onClick={() =>{
                      if(loc.pathname.includes("/profile")){
                        setPasswordSuccessFullChange(false)
                      }
                      else{
                        setPasswordSuccessFullChange(false)
                        navigate('/login')
                      }
                      }}
                  >
                  <IoMdClose color="#000000" size={20} />
                  </button>
                </div>
                {/*body*/}
                <div className="relative pt-0 p-6 h-full justify-center  flex flex-col items-center">
                    <img src="/success.webp" className="mb-3 w-[80px] h-[80px]" alt="" />
                 <h3 className="font-semibold text-[24px] leading-[29px] mb-3 capitalize" >password updated succesfully!</h3>
                 <p className="text-[#858585] text-[13px] text-center font-medium leading-[13px] " >Your Password has been updated successfully.</p>
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