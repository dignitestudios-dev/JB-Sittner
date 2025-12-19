import React, { useContext, useEffect, useState } from "react";
import { IoMdArrowBack } from "react-icons/io";
import { NavLink, useNavigate } from "react-router-dom";
import { ModernTimePicker } from "../../components/Picker/TimePicker";
import DatePicker from "../../components/Picker/DatePicker";
import { MyContext } from "../../context/GlobalContext";
import { addDoc, collection, db, doc, getDoc, getDocs, query, where } from "../../firbase/FirebaseInit";
import { toast } from "react-toastify";

export default function CreateNotification() {
  const { SelectedTime, SelectedDate,Employee,loader,setLoader } = useContext(MyContext);
  const navigate = useNavigate("");
  const [tokens, setTokens] = useState([]);
  const [Notification, SetNotification] = useState({
    title: "",
    description: "",
  });

  useEffect(() => {
    const fetchTokens = async () => {
      try {
        const fcmTokenRef = doc(db, "fcmTokens", "tokenList");
        const fcmTokenDoc = await getDoc(fcmTokenRef);

        if (fcmTokenDoc.exists()) {
          const tokensArray = fcmTokenDoc.data().tokens || [];
          console.log("Tokens array:", tokensArray); 
          setTokens(tokensArray); 
        } else {
          console.log("No tokens document found");
        }
      } catch (error) {
        console.error("Error fetching tokens:", error);
      }
    };

    fetchTokens(); 


  }, []);

  const HandleInput = (e) => {
    const { name, value } = e.target;
    SetNotification({
      ...Notification,
      [name]: value,
    });
  };

  const generateUniqueId = async () => {
    const randomId = Math.floor(100000 + Math.random() * 900000).toString(); 
    const existingEmployee = await getDocs(query(collection(db, "notification"), where("notificationId", "==", randomId)));
    
    if (!existingEmployee.empty) {
        return generateUniqueId(); 
    }
    return randomId;
};


  const UploadNotification = (e) => {
    e.preventDefault();
    setLoader(true)
    const myPromise = new Promise(async (resolve, reject) => {
        try {
          const uniqueId = await generateUniqueId(); 
            await addDoc(collection(db, "notification"), {
                notificationId:uniqueId,
                title:Notification.title,
                description:Notification.description,
                time:SelectedTime,
                date:SelectedDate,
                status:"Scheduled",
                toast:[],
                author:Employee,
                seen:[]
            });
            resolve("Notification Created")
        } catch (error) {
            reject(error.message);
        }
    });

    toast.promise(myPromise, {
        pending: "Creating Notification...",
        success: (data) => data,
        error: (error) => error,
    }).then(() => {
      setLoader(false)
        navigate("/notification");
    });
  };


  return (
    <div class="bg-[#F7F7F7] h-[80vh] py-5 px-5 ">
      <NavLink
        to={"/notification"}
        className="font-semibold text-[24px] leading-[29px] flex items-center"
      >
        {" "}
        <IoMdArrowBack size={25} className="mr-2" /> Create Notification
      </NavLink>
      <div class="bg-[#FFFFFF] mb-3 h-full border rounded-[10px] border-[#E4E4E4] mt-6 px-3 py-3 lg:py-5 lg:px-10">
        <form onSubmit={(e) => UploadNotification(e)}>
          <div className="mt-5 grid grid-cols-1 gap-5  lg:grid-cols-2">
            <div className="mb-1 col-span-2">
              <label htmlFor="" className="text-xs font-normal">
                Title of Notification
              </label>
              <input
                type="text"
                onChange={HandleInput}
                value={Notification.title}
                name="title"
                style={{ border: "1px solid #00000030" }}
                className="bg-white  text-gray-900 text-sm rounded-[12px]  h-[46px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]"
                placeholder="Type Here...."
                required
              />
            </div>
            <div className="mb-1 col-span-2">
              <label htmlFor="" className="text-xs font-normal">
                Description of Notification
              </label>
              <textarea
                type="text"
                value={Notification.description}
                onChange={HandleInput}
                name="description"
                className="bg-white border border-gray-300 text-gray-900 text-sm rounded-[12px] h-[75px] mt-1  block w-full p-2.5 focus:outline-[#0A8A33]  "
                placeholder="Type Here...."
                required
              ></textarea>
            </div>
            <div className="mb-3 grid grid-cols-1  lg:grid-cols-2  col-span-2 lg:col-span-1">
              <DatePicker />
              <ModernTimePicker />
            </div>
          </div>
          <div className="flex items-center gap-5 mt-5">
            <button
              type="submit"
              disabled={loader?loader:false}
              className="text-white bg-[#0A8A33]  rounded-lg  w-[150px] h-[50px]  px-5 py-2.5 text-center"
            >
              Save
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
