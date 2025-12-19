import { GoAlertFill } from "react-icons/go";
export default function DeleteMessageModal({deleteModal,setDeleteModal,handleDelete}) {
  
    return (
        <>
            {deleteModal ? (
                <>
                    <div
                        className="justify-center  items-center flex overflow-x-hidden overflow-y-auto fixed inset-0 z-50 outline-none focus:outline-none">
                        <div className="w-[350px] h-[250px] ">
                            {/*content*/}
                            <div className="border-0  rounded-[16px] shadow-lg  flex flex-col w-full bg-white outline-none focus:outline-none">                                
                                {/*body*/}
                                <div className="px-6 py-6 flex flex-col items-center">                                    
                                    <GoAlertFill size={40} color="#EE3131" />
                                    <h3 className="font-semibold text-[20px] leading-[29px] mb-3 capitalize" >Delete Message</h3>
                                    <p className="text-[#565656] text-[13px] text-center font-medium leading-[15px] " >Are you sure you want to delete this message?</p>
                                    <div className="flex items-center w-full mt-2 justify-between" >
                                        <button className={`flex text-xs w-[140px] text-center bg-[#ECECEC] h-[44px] flex items-center justify-center rounded-[8px] font-semibold mt-3 px-4 py-2   `} 
                                         onClick={() => setDeleteModal(false)}
                                        >No</button>
                                        <button className={`flex text-xs w-[140px] text-white text-center bg-[#EE3131] h-[44px] flex items-center justify-center rounded-[8px] font-semibold mt-3 px-4 py-2   `}
                                         onClick={() =>{
                                            setDeleteModal(false);
                                            handleDelete()
                                            }}
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