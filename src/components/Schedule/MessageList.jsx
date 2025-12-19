import React, { useContext, useEffect, useState } from "react";
import { NavLink } from "react-router-dom";
import { MyContext } from "../../context/GlobalContext";
import {
  collection,
  db,
  onSnapshot,
  query,
  getDocs,
  addDoc,
  updateDoc,
  orderBy,
} from "../../firbase/FirebaseInit";
import Loader from "../../global/Loader";
import Cookies from "js-cookie";
import moment from "moment";
import 'moment-timezone';
export default function MessageList() {
  const {
    DeleteSchedule,
    setIsDeleteSchedule,
    setIsDeleteProfile,
    setLoader,
    loader,
    updateCount,
    setUpdateCount
  } = useContext(MyContext);
  const [scheduled, setScheduled] = useState([]);
  
  const getEmployees = () => {
    const employeesRef = collection(db, "scheduled");
    const employeeQuery = query(employeesRef, orderBy("createdAt", "desc"));
    setLoader(true);
  
    const unsubscribe = onSnapshot(
      employeeQuery,
      (querySnapshot) => {
        const employeeData = querySnapshot.docs.map((doc) => ({
          docId: doc.id,
          ...doc.data(),
        }));
        setScheduled(prevData => {          
          if (JSON.stringify(prevData) !== JSON.stringify(employeeData)) {
            return employeeData; 
          }
          return prevData; 
        });
  
        setLoader(false);
      },
      (error) => {
        console.error("Error fetching data: ", error);
        setLoader(false);
      }
    );
  
    setUpdateCount((prev) => prev + 1);
    return unsubscribe;
  };
  
  

  
  useEffect(() => {
    const unsubscribe = getEmployees();
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    const checkAndSendNotifications = async (empData) => {
      const notificationsRef = collection(db, "scheduled");
      const messageRef = collection(db, "message");

      const querySnapshot = await getDocs(notificationsRef);
      const updates = [];

      const now = moment.tz("America/Denver"); 

      querySnapshot.forEach((doc) => {
        const data = doc.data();
        
        const notificationDate = moment.tz(`${data.date} ${data.time}`, "MM/DD/YYYY h:mm A", "America/Denver");
        if (notificationDate.isSameOrBefore(now) && data.status === "pending") {
          updates.push(updateDoc(doc.ref, { status: "Sent" }));
          updates.push(addDoc(messageRef, {
            time: data?.time,
            message: data?.message,
            UserMsgSeen: [],
            images: data?.images,
            id: data.id,
            type: data?.type,
            createdAt: new Date(),
            employeeId: empData?.id,
          }));
        }
      });

      await Promise.all(updates);
    };

    const cookieData = Cookies.get("employe");
    if (cookieData) {
      const empData = JSON.parse(cookieData);
      const intervalId = setInterval(() => {
        checkAndSendNotifications(empData);
      }, 5000); 

      return () => clearInterval(intervalId);
    }
  }, [updateCount]);
  
  const [FilterMessages, setFilterMessages] = useState([]);
  useEffect(() => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);  
    const filteredNotifications = scheduled.filter(item => {
      const itemDate = item.createdAt.toDate();  
      return itemDate >= sevenDaysAgo; 
    });
  
    setFilterMessages(filteredNotifications);
  }, [scheduled]);
  

  return (
    <div className="bg-[#FFFFFF] border  scroll-box  overflow-auto h-[70vh]  rounded-[10px] border-[#E4E4E4] mt-6 py-3 px-3 lg:py-6  lg:px-10">
      {loader ? (
        <Loader />
      ) : scheduled.length === 0 ? (
        <div className="text-center text-gray-500 mt-4">
          No scheduled items available.
        </div>
      ) : (
        FilterMessages.map((item, i) => (
          <div
            key={i}
            className="flex mb-2 items-center justify-between border-b-2 py-4 border-[#F4F4F4]"
          >
            <div className="msg w-[100%] md:w-[80%]  ">
              {item.message && (
                <p className="text-base font-normal text-[#18181880]">
                  {item.message}
                </p>
              )}
              <div className="flex items-center flex-wrap gap-2 lg:gap-2 mt-2  lg:grid-cols-10">
                {item?.images?.length > 0 &&
                  item?.images?.map((img, i) =>
                    item.type[i].includes("image") ? (
                      <div>
                        <img
                          src={img.url}
                          alt=""
                          className="rounded-lg w-[70px] h-[40px] "
                        />
                      </div>
                    ) : (
                      <div>
                        <img
                          src={"/pdf.png"}
                          alt=""
                          className="rounded-lg h-[50px] "
                        />
                      </div>
                    )
                  )}
              </div>
              <div className="flex items-center justify-between mt-3 ">
                <div className="flex items-center">
                <span className="flex items-center text-[#5C5C5C] text-xs">
                  <img
                    src="/agenda.png"
                    className="w-5 mr-2"
                    alt=""
                    srcset=""
                  />
                  {moment.tz(`${item.date}`, "MM/DD/YYYY h:mm A", "America/Denver").format("MMM/DD/YYYY ")  }
                </span>
                <span className="flex items-center ml-3 text-[#5C5C5C] text-xs">
                  <img src="/clock.png" className="w-5 mr-2" alt="" srcset="" />
                  {item.time}
                </span>
                </div>
                <div  > 
                {
            item.status != "pending" ? (
              <span className="bg-[#41C54E26] flex md:hidden text-[#41C54E] text-xs font-medium me-2 px-4 py-2 rounded-full  ">
                Sent
              </span>
            ) : (
              <div className="flex md:hidden items-center">
                <button
                  className="bg-transparent"
                  onClick={() => {
                    setIsDeleteProfile(item);
                    setIsDeleteSchedule(!DeleteSchedule);
                  }}
                >
                  <img src="/trash.png" className="w-5" alt="" srcset="" />
                </button>
                <NavLink
                  to={"/editschedule"}
                  state={{ data: item,collection:"scheduled" }}
                  className="ml-2 bg-transparent "
                >
                  <img
                    src="/whiteedit.png"
                    state={{ data: item }}
                    className="w-5"
                    alt=""
                    srcset=""
                  />
                </NavLink>
              </div>
            )}
              </div>
              </div>
            </div>
            {
            item.status != "pending" ? (
              <span className="bg-[#41C54E26] hidden md:block text-[#41C54E] text-xs font-medium me-2 px-4 py-2 rounded-full  ">
                Sent
              </span>
            ) : (
              <div className="hidden md:flex items-center">
                <button
                  className="bg-transparent"
                  onClick={() => {
                    setIsDeleteProfile(item);
                    setIsDeleteSchedule(!DeleteSchedule);
                  }}
                >
                  <img src="/trash.png" className="w-5" alt="" srcset="" />
                </button>
                <NavLink
                  to={"/editschedule"}
                  state={{ data: item,collection:"scheduled" }}
                  className="ml-2 bg-transparent "
                >
                  <img
                    src="/whiteedit.png"
                    state={{ data: item }}
                    className="w-5"
                    alt=""
                    srcset=""
                  />
                </NavLink>
              </div>
            )}
          </div>
        ))
      )}
    </div>
  );
}
