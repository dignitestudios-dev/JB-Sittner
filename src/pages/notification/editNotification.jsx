import React, { useContext, useEffect, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import { ModernTimePicker } from "../../components/Picker/TimePicker";
import DatePicker from "../../components/Picker/DatePicker";
import { db, doc, getDoc, storage, updateDoc } from "../../firbase/FirebaseInit";
import { MyContext } from "../../context/GlobalContext";
import { toast } from "react-toastify";

export default function EditNotification() {
  const navigate = useNavigate("");
  const loc = useLocation();
  const { SelectedTime, SelectedDate } = useContext(MyContext);
  
  const [Notification, SetNotification] = useState({
    title: "",
    description: "",
  });

  useEffect(() => {
    SetNotification({
      title: loc?.state?.data?.title,
      description: loc?.state?.data?.description,
      time: loc?.state?.data?.time,
      date: loc?.state?.data?.date,
    });
    // getMemberRec();
  }, [loc?.state?.data]);

  

  const HandleInput = (e) => {
    const { name, value } = e.target;
    SetNotification({
      ...Notification,
      [name]: value,
    });
  };

  const UpdateNotification = (e) => {
    console.log(Notification,"record");
    
    e.preventDefault();
        const washingtonRef = doc(db, "notification",loc?.state?.data?.docId);
        const myPromise = new Promise(async (resolve, reject) => {
            try {
              await updateDoc(washingtonRef, {
                title:Notification.title,
                description:Notification.description,
                time:SelectedTime,
                date:SelectedDate,
                status:"Scheduled",
                seen:""
              });
              resolve("Notification Update");
            } catch (error) {
              reject(error.message);
            }
          });
          toast
            .promise(myPromise, {
              pending: "Updating Notification...",
              success: (data) => data,
              error: (error) => error,
            })
            .then(() => {
                navigate("/notification")   
            });
      };



  return (
    <div class="bg-[#F7F7F7] h-[80vh] py-5 px-5 ">
      <NavLink
        to={"/notification"}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Edit Notification
      </NavLink>
      <div class="bg-[#FFFFFF] mb-3 h-full border rounded-[10px] border-[#E4E4E4] px-3 py-3 mt-6 lg:py-5 lg:px-10">
        <form onSubmit={(e) => UpdateNotification(e)}>
          <div className="mt-5 grid grid-cols-1 gap-5  lg:grid-cols-2">
            <div className="mb-1 col-span-2">
              <label htmlFor="" className="text-xs font-normal">
                Title of Notification
              </label>
              <input
                type="text"
                name="title"
                value={Notification.title}
                onChange={HandleInput}
                style={{ border: "1px solid #00000030" }}
                className="bg-white  text-gray-900 text-sm rounded-[12px]  h-[46px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]"
                placeholder="Type Here...."
              />
            </div>
            <div className="mb-1 col-span-2">
              <label htmlFor="" className="text-xs font-normal">
                Description of Notification
              </label>
              <textarea
                type="text"
                name="description"
                value={Notification.description}
                onChange={HandleInput}
                className="bg-white border border-gray-300 text-gray-900 text-sm rounded-[12px] h-[75px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  "
                placeholder="Type Here...."
              ></textarea>
            </div>

            <div className="mb-3 grid grid-cols-1  lg:grid-cols-2 col-span-2 lg:col-span-1">
              <DatePicker date={Notification.date} />
              <ModernTimePicker time={Notification.time} />
            </div>
          </div>
          <div className="flex items-center gap-5 mt-5">
            <button            
              type="submit"
              className="text-white bg-[#0A8A33]  rounded-lg  w-[150px] h-[50px]  px-5 py-2.5 text-center"
            >
              Update
            </button>
            <NavLink
              to={"/notification"}
              className="bg-[#F1F1F1] font-bold rounded-lg  w-[150px] h-[50px]  px-5 py-2.5 text-center"
            >
              Cancel
            </NavLink>
          </div>
        </form>

        <div></div>
      </div>
    </div>
  );
}
