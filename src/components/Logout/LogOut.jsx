import React, { useContext} from "react";
import { MyContext } from "../../context/GlobalContext";
import { useNavigate } from "react-router-dom";
import { IoExit } from "react-icons/io5";
import Cookies from 'js-cookie';
export default function LogOut() {
    const {LogOut,setIsLogOut,setEmployee}=useContext(MyContext);
    const navigate=useNavigate("");
   const handleLogOut=()=>{
       Cookies.set('employe',""); 
       setEmployee({});          
       setIsLogOut(false)
       navigate("/login")
   }

    
    return (
        <>
            {LogOut ? (
                <>
                    <div
                        className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
                        <div className="w-[350px] h-[250px] ">
                            {/*content*/}
                            <div className="border-0  rounded-[16px] shadow-lg  flex flex-col w-full bg-white outline-none focus:outline-none">                                
                                {/*body*/}
                                <div className="px-6 py-6 flex flex-col items-center">
                                    <IoExit size={40} color="#EE3131"/>
                                    <h3 className="font-semibold text-[20px] leading-[29px] mb-3 capitalize" >Logout</h3>
                                    <p className="text-[#565656] text-[13px] text-center font-medium leading-[15px] " >Are you sure you want to log out of your account?</p>
                                    <div className="flex items-center w-full mt-2 justify-between" >
                                        <button className={`flex text-xs w-[140px] text-center bg-[#ECECEC] h-[44px] flex items-center justify-center rounded-[8px] font-semibold mt-3 px-4 py-2   `} 
                                         onClick={() => setIsLogOut(false)}
                                        >No</button>
                                        <button className={`flex text-xs w-[140px] text-white text-center bg-[#EE3131] h-[44px] flex items-center justify-center rounded-[8px] font-semibold mt-3 px-4 py-2   `}
                                         onClick={() => handleLogOut()}
                                        >Yes</button>                                        
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