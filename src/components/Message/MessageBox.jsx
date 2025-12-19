import React, { useContext, useEffect, useRef, useState } from "react";
import { GrAttachment } from "react-icons/gr";
import { RiSendPlaneFill } from "react-icons/ri";
import { MdDeleteSweep, MdOutlineFilePresent } from "react-icons/md";
import { MyContext } from "../../context/GlobalContext";
import Loader from "../../global/Loader";
import {
  addDoc,
  collection,
  db,
  deleteDoc,
  deleteObject,
  doc,
  getCountFromServer,
  getDocs,
  getDownloadURL,
  onSnapshot,
  orderBy,
  query,
  ref,
  storage,
  updateDoc,
  uploadBytesResumable,
  where,
} from "../../firbase/FirebaseInit";
import { toast } from "react-toastify";
import { useLocation } from "react-router-dom";
import { IoMdClose } from "react-icons/io";
import IonPhotoViewer from "@codesyntax/ionic-react-photo-viewer";
import { HiOutlineDotsVertical } from "react-icons/hi";
import { CiTrash } from "react-icons/ci";
import DeleteMessageModal from "./DeleteMessage";
export default function MessageBox() {
  const {
    LookScreen,
    setLookScreen,
    setIsMessageInfo,
    setIviewImage,
    setSideDraw,
    hideLookAhed,
    setLookAhedDraw,
    Employee,
    setGroupName,
    GroupName,
    setModalImageUrl,
    setIsMessageSeen,
    setIsAttachments,
    setLoader,
    loader,
    msgSeenEmp,
    isMessageSeen,
    setMsgSeenEmp,
  } = useContext(MyContext);
  const [Message, SetMessages] = useState([]);
  const [UserMsg, setUserMsg] = useState("");
  const [images, setImages] = useState([]);
  const [sentMessage, setSentMessage] = useState(0);
  const [sentLoad, setSentLoad] = useState(false);
  const [deleteModal,setDeleteModal] = useState(false);
  const loc = useLocation();
  const msgBodyScroll = useRef();
  const [EmployeeCount, setEmployeeCount] = useState();
  const textareaRef = useRef(null);
  const [currentInd, setCurrentInd] = useState();
  const [selectedMessage,setSelectedMessage]=useState(false);
  
  const handleInputResize = () => {
    if (textareaRef.current) {
      if (UserMsg.length > 30) {
        textareaRef.current.style.height = "auto"; // Reset height to auto
        textareaRef.current.style.height = `${
          textareaRef.current.scrollHeight > 100
            ? 100
            : textareaRef.current.scrollHeight
        }px`;
      }
    }
  };

  useEffect(() => {
    if (sentMessage === 0) {
      setLoader(true);
    }

    const q = query(collection(db, "message"), orderBy("createdAt"));
    const unsubscribe = onSnapshot(
      q,
      (querySnapshot) => {
        const msgArray = [];
        querySnapshot.forEach((doc) => {
          msgArray.push({ docId: doc.id, ...doc.data() });
        });
        SetMessages(msgArray);
        console.log(msgArray, "msg--->array");

        setIsAttachments(msgArray);
        setLoader(false);
        setTimeout(() => {
          if (msgBodyScroll.current) {
            msgBodyScroll.current.scrollTop =
              msgBodyScroll.current.scrollHeight;
          }
        }, 600);
      },

      (error) => {
        console.error("Error fetching messages: ", error);
        setLoader(false);
      }
    );

    return () => {
      setLoader(false);
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      const groupQuery = query(collection(db, "group"));
      const unsubscribe = onSnapshot(groupQuery, (querySnapshot) => {
        querySnapshot.forEach((doc) => {
          setGroupName({ docId: doc.id, ...doc.data() });
        });
      });

      const employeeQuery = query(
        collection(db, "employee"),
        where("role", "==", "user")
      );
      const snapshot = await getCountFromServer(employeeQuery);
      setEmployeeCount(snapshot.data().count);
      return () => unsubscribe();
    };

    fetchData();
  }, []);

  const generateUniqueId = async () => {
    const randomId = Math.floor(100000 + Math.random() * 900000).toString();
    const existingEmployee = await getDocs(
      query(collection(db, "message"), where("id", "==", randomId))
    );
    if (!existingEmployee.empty) {
      return generateUniqueId();
    }
    return randomId;
  };
  const HandleMessage = async (e) => {
    e.preventDefault();
    setSentLoad(true);
    const trimmedUserMsg = UserMsg;
    if (trimmedUserMsg === "" && images.length === 0) {
      toast.error("Please enter a message or upload an image.");
      setSentLoad(false);
      return;
    }
    // Create a loading toast
    const loadingToastId = toast.loading("Sending your message...");

    const scheduledRef = collection(db, "message");
    const imageUrls = [];
    const docType = [];

    setUserMsg("");
    try {
      const uniqueId = await generateUniqueId();
      for (const image of images) {
        const storageRef = ref(storage, `images/${uniqueId + image.name}`);
        await uploadBytesResumable(storageRef, image);
        const url = await getDownloadURL(storageRef);
        imageUrls.push({ url: url, name: uniqueId + image.name });
        docType.push(image.type);
      }
      const options = { timeZone: "America/Denver" };
      await addDoc(scheduledRef, {
        date: new Date().toLocaleDateString(),
        time: new Intl.DateTimeFormat("en-US", {
          ...options,
          hour: "numeric",
          minute: "2-digit",
          hour12: true,
        }).format(new Date()),
        message: UserMsg,
        id: uniqueId,
        images: imageUrls,
        type: docType,
        UserMsgSeen: [],
        createdAt: new Date(),
        isReminder: false,
        employeeId: Employee.id,
      });
      setImages([]);
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `50px`;
      toast.update(loadingToastId, {
        render: "Message sent successfully!",
        type: "success",
        isLoading: false,
        autoClose: 3000,
      });

      setSentMessage((prev) => prev + 1);
    } catch (error) {
      console.error("Failed to schedule:", error);

      toast.update(loadingToastId, {
        render: "Failed to send message. Please try again.",
        type: "error",
        isLoading: false,
        autoClose: 3000,
      });
    } finally {
      setSentLoad(false);
    }
  };

  const handleImageChange = (e) => {
    const newImages = Array.from(e.target.files);
    setImages((prev) => [...prev, ...newImages]);
  };

  const handleChange = (e) => {
    if (e.target.value == "") {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `50px`;
    }
    setUserMsg(e.target.value);
  };

  const MessageSeen = async () => {
    if (loc.pathname === "/") {
      for (const item of Message) {
        const scheduledRef = doc(db, "message", item.docId);
        const hasSeen = item?.UserMsgSeen?.some(
          (user) => user.EmployeeId == Employee.id
        );
        if (!hasSeen) {
          const currentTime = new Date();
          const options = { timeZone: "America/Denver" };
          // Format the date and time
          const formattedDate = new Intl.DateTimeFormat("en-US", {
            ...options,
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
          }).format(currentTime);
          const formattedTime = new Intl.DateTimeFormat("en-US", {
            ...options,
            hour: "numeric",
            minute: "2-digit",
            hour12: true,
          }).format(currentTime);

          // Combine date and time
          const seenData = {
            seenTime: `${formattedDate} ${formattedTime}`,
            EmployeeId: Employee.id,
          };

          await updateDoc(scheduledRef, {
            UserMsgSeen: [...item.UserMsgSeen, seenData],
          });
        }
      }
    }
  };

  useEffect(() => {
    MessageSeen();
  }, [Message]);

  const [employee, setEmployee] = useState([]);

  const getEmploye = () => {
    const employeesRef = collection(db, "employee");
    const employeeQuery = query(employeesRef);
    const unsubscribe = onSnapshot(employeeQuery, (querySnapshot) => {
      const employeeData = querySnapshot.docs.map((doc) => ({
        docid: doc.id,
        ...doc.data(),
      }));
      setEmployee(employeeData);
    });
    return unsubscribe;
  };
  useEffect(() => {
    const unsubscribe = getEmploye();
    return () => unsubscribe();
  }, []);


  const [isPreviewOpen, setIsPreviewOpen] = useState(false);

  useEffect(() => {
    const handleKeydown = (event) => {
      if (isPreviewOpen) {
        event.preventDefault();
      }
    };
    if (isPreviewOpen) {
      window.addEventListener("keydown", handleKeydown);
    } else {
      window.removeEventListener("keydown", handleKeydown);
    }
    return () => {
      window.removeEventListener("keydown", handleKeydown);
    };
  }, [isPreviewOpen]);

  const separateLinks = (message) => {
    // Define a regex to match URLs
    const urlRegex = /(https?:\/\/[^\s]+)/g;

    // First, replace the newline characters with a special string marker
    const messageWithLineBreaks = message.replace(/\n/g, " <NEWLINE> ");

    // Split the message by URLs and the special NEWLINE marker
    const parts = messageWithLineBreaks.split(
      /(https?:\/\/[^\s]+| <NEWLINE> )/g
    );

    return parts.map((part, index) => {
      // If the part is a URL, render as a clickable link
      if (part.match(urlRegex)) {
        return (
          <a
            key={index}
            href={part}
            target="_blank"
            rel="noopener noreferrer"
            className={`underline ${
              Employee?.role === "user" ? "text-blue-500" : ""
            }`}
          >
            {part}
          </a>
        );
      }

      // If the part is the special marker for newlines, render as a <br />
      if (part === " <NEWLINE> ") {
        return <br key={index} />;
      }

      // Otherwise, render as normal text
      return <span key={index}>{part}</span>;
    });
  };

  const [FilterMessages, setFilterMessages] = useState([]);
  useEffect(() => {
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 14);
    const filteredNotifications = Message.filter((item) => {
      const itemDate = item.createdAt.toDate();
      return itemDate >= sevenDaysAgo;
    });
    setFilterMessages(filteredNotifications);
  }, [Message]);

  const groupMessagesByDate = (messages) => {
    return messages.reduce((acc, message) => {
      const firebaseTimestamp = message.createdAt;
      const messageDate = new Date(
        firebaseTimestamp.seconds * 1000
      ).toLocaleDateString();
      if (!acc[messageDate]) {
        acc[messageDate] = [];
      }
      acc[messageDate].push(message); // push the message into the correct date group
      return acc;
    }, {});
  };

  const handleDelete = async () => {
    try {
      await deleteDoc(doc(db, "message", selectedMessage?.docId));
      if (selectedMessage.images.length > 0) {
        selectedMessage.images.forEach((el) => {
          console.log(el);
          const desertRef = ref(storage, `images/${el?.name}`);
          deleteObject(desertRef)
            .then(() => {
              console.log("deleted Image");
            })
            .catch((error) => {
              console.log(error);
            });
        });
      }
      console.log(selectedMessage, "success fulyy deleted");
    } catch (error) {
      console.log(error);
    }

    console.log(selectedMessage, "test");
  };

  const groupedMessages = groupMessagesByDate(FilterMessages);
  return (
    <div className="bg-[#FFFFFF] w-full h-[78vh] md:h-[80%] lg:h-[630px] relative rounded-[24px]">
      {/* Message Head */}
      <div className="chathead h-[10%] px-2 md:px-5 py-2 md:py-3 border-b border-[#E1E1E1]">
        <div className="flex justify-between items-center ">
          <div className="flex items-center">
            <div>
              {GroupName.groupimg ? (
                <img
                  src={GroupName.groupimg}
                  class="rounded-[50%] object-cover cursor-pointer  w-[30px] h-[30px] lg:w-[50px] lg:h-[50px]"
                  alt=""
                />
              ) : (
                <img
                  src={"noprofile.png"}
                  class="rounded-[50%] object-cover cursor-pointer w-[30px] h-[30px] lg:w-[50px] lg:h-[50px]"
                  alt=""
                />
              )}
            </div>
            <div
              className="ml-2 cursor-pointer "
              onClick={() =>
                (Employee?.role == "admin" || !hideLookAhed) &&
                (hideLookAhed
                  ? setLookScreen(!LookScreen)
                  : setLookAhedDraw(true))
              }
            >
              <h2 className="font-semibold text-base   lg:text-2xl lg:leading-[29px]">
                {GroupName.group_name}
              </h2>
              <p className="text-[#8A8A8A] text-[13px] font-normal">
                {EmployeeCount} members
              </p>
            </div>
          </div>
          {Employee?.role == "admin" && (
            <div className="ms-auto">
              <button
                className="text-white bg-[#0A8A33] hover:bg-green-800  rounded-full text-sm p-2.5 text-center flex lg:hidden items-center"
                onClick={() => {
                  setSideDraw(true);
                }}
              >
                <MdOutlineFilePresent className="text-base lg:text-2xl" />
              </button>
            </div>
          )}
          <div></div>
        </div>
      </div>
      {/* Message Body */}
      <div
        ref={msgBodyScroll}
        className={`md:chat-body ${
          Employee?.role == "admin"
            ? "h-[80%] lg:h-[440px]"
            : "h-[80%] lg:h-[540px]"
        }  scroll-box  overflow-auto`}
      >
        {/* Day Timer */}

        {loader ? (
          <Loader />
        ) : (
          <>
            {/* Messages */}
            {Object.keys(groupedMessages).map((date, index) => (
              <div key={index}>
                {/* Show the date only once for each group */}
                <div className="flex justify-center py-2">
                  <span className="bg-[#F4F4F4] rounded-full px-2 py-1 text-xs font-normal">
                    {date}
                  </span>
                </div>

                {/* Render all the messages for that specific date */}
                {groupedMessages[date].map((msg, i) => (
                  <div
                    key={i}
                    className={`left-side ${
                      Employee?.role == "admin" && "ms-auto"
                    } mb-3 px-3 py-3 msg-list w-auto lg:max-w-[100%]`}
                  >
                    {Employee?.role == "user" && (
                      <div className="username mb-3">
                        <h2 className="font-semibold text-sm leading-[14px]">
                          Admin
                        </h2>
                      </div>
                    )}
                    <div className="w-full  py-2">
                      {msg.message && (
                        <div
                          className="flex"
                          onMouseLeave={(e) => {
                            console.log(currentInd)
                            setCurrentInd(null)
                          }}
                        >
                          <div
                            onMouseOver={() =>{
                              
                              setCurrentInd(msg.docId)
                              
                              console.log(msg.docId)
                              }}
                            className={`${
                              Employee?.role == "admin"
                                ? "bg-[#0A8A33] text-white ms-auto"
                                : "bg-[#F4F4F4] "
                            } w-full rounded-2xl rounded-tr-none break-words lg:w-[30%]  px-2 py-3 text-xs font-normal`}
                          >
                            <span>{separateLinks(msg.message)}</span>
                          </div>
                            {currentInd ==  msg.docId&& (
                          <div>
                              <button
                                onClick={() => {
                                  setSelectedMessage(msg);
                                  setDeleteModal(!deleteModal);
                                }}
                              >
                                <CiTrash size={20} color="#797C7B" />
                              </button>
                          </div>
                            )}
                        </div>
                      )}
                      {msg.images.length > 0 && (
                        <div
                        onMouseLeave={() => setCurrentInd(null)}
                        onMouseOver={() => setCurrentInd(i)}
                          className={`w-full py-3 grid grid-cols-3 lg:grid-cols-5 gap-3  ${
                            Employee?.role == "admin" && ""
                          }`}
                        >
                          {msg.images.map((img, index) =>
                            msg.type[index]?.includes("image") ? (
                              <div
                                key={index}
                                className="rounded-xl flex justify-center items-center bg-[#F4F4F4] text-xs font-normal"
                              >
                                <IonPhotoViewer src={img.url}>
                                  <img
                                    alt="Image alt"
                                    className="cursor-pointer rounded-md max-h-[80px] w-auto max-w-[100%] block"
                                    src={img.url}
                                  />
                                </IonPhotoViewer>
                              </div>
                            ) : msg.type[index]?.includes("video") ? (
                              <div
                                key={index}
                                className="rounded-xl col-span-2 md:col-span-1 flex justify-center items-center bg-[#F4F4F4] text-xs font-normal"
                              >
                                <video
                                  width="400"
                                  className="cursor-pointer max-w-[100%] h-auto rounded-md"
                                  onClick={() => {}}
                                  controls
                                  src={img.url}
                                />
                              </div>
                            ) : msg.type[index]?.includes("spreadsheetml") ? (
                              <div
                                key={index}
                                className="rounded-xl flex justify-center px-2 py-2 bg-[#F4F4F4] text-xs font-normal"
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
                                    alt="xlsx"
                                  />
                                </a>
                              </div>
                            ) : (
                              <div
                                key={index}
                                className="rounded-xl flex justify-center px-2 py-2 bg-[#F4F4F4] text-xs font-normal"
                              >
                                <a
                                  href={img.url}
                                  download
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  <img
                                    src="/pdf.png"
                                    className="cursor-pointer"
                                    alt="pdf"
                                  />
                                </a>
                              </div>
                            )
                          )}
                           <div>
                            {currentInd == msg?.docId && (
                              <button
                                onClick={() => {
                                  setSelectedMessage(msg);
                                  setDeleteModal(!deleteModal);
                                }}
                              >
                                <CiTrash size={20} color="#797C7B" />
                              </button>
                            )}
                          </div>
                        </div>
                      )}

                    </div>
                    <div className="flex items-center gap-1 justify-end">
                      {Employee?.role == "admin" && (
                        <div className="flex items-center gap-2 ">
                          <img
                            src="/tick-double.png"
                            onClick={() => {
                              const seenEmployeeData = msg.UserMsgSeen.map(
                                (user) => ({
                                  EmployeeId: user.EmployeeId,
                                  seenTime: user.seenTime,
                                })
                              );
                              const seenEmployeeIds = seenEmployeeData.map(
                                (user) => user.EmployeeId
                              );
                              const getMsgSeenEmp = employee
                                .map((emp) => {
                                  const seenRecord = seenEmployeeData.find(
                                    (user) => user.EmployeeId === emp.id
                                  );
                                  return {
                                    ...emp,
                                    seenTime: seenRecord
                                      ? seenRecord.seenTime
                                      : null,
                                  };
                                })
                                .filter((emp) =>
                                  seenEmployeeIds.includes(emp.id)
                                );

                              setIsMessageSeen(msg.UserMsgSeen);
                              setMsgSeenEmp(getMsgSeenEmp);
                              setIsMessageInfo(true);
                            }}
                            className="w-5 cursor-pointer ml-1"
                            alt=""
                          />
                        </div>
                      )}
                      <span className="text-[10px] font-normal leading-[10px] text-[#797C7B]">
                        {msg?.time}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ))}
          </>
        )}
      </div>
      {/* Send Message */}
      {Employee?.role == "admin" && (
        <div className="pb-2 h-[15%]  w-full bottom-0">
          {images.length > 0 && (
            <div className="shadow-xl bg-slate-100 px-2 py-2 mx-auto flex items-center gap-5 nowrap  absolute bottom-[35px] md:bottom-[110px] w-full  custom-scroll-bar  overflow-auto">
              {Array.from(images).map((image, targetIndex) => (
                <div key={targetIndex}>
                  <div className="flex justify-end px-3 pb-2">
                    <button
                      className="bg-transparent"
                      onClick={() => {
                        const newArray = images.filter(
                          (item, index) => index !== targetIndex
                        );
                        setImages(newArray);
                      }}
                    >
                      <IoMdClose className="text-red-500" />
                    </button>
                  </div>

                  {image.type?.includes("image") ? (
                    <img
                      src={URL.createObjectURL(image)}
                      alt=""
                      className="h-[60px] rounded-md w-[60px]"
                      srcset=""
                    />
                  ) : image.type.includes("video") ? (
                    <img
                      src={"/video.webp"}
                      alt=""
                      className="h-[60px] rounded-md w-[60px]"
                      srcset=""
                    />
                  ) : image.type?.includes("spreadsheetml") ? (
                    <img
                      src={"/xl.webp"}
                      alt=""
                      className="h-[60px] rounded-md w-[60px]"
                      srcset=""
                    />
                  ) : (
                    <img
                      src={"/pdf.webp"}
                      alt=""
                      className="h-[60px] rounded-md w-[60px]"
                      srcset=""
                    />
                  )}
                </div>
              ))}
            </div>
          )}
          <form
            onSubmit={(e) => HandleMessage(e)}
            className="w-100 bg-white px-3 p-3 lg:px-5 py-5  flex items-center  w-full h-full justify-center gap-5 "
          >
            <div className="relative h-full w-[85%] mt-3">
              <div className="absolute inset-y-6 md:inset-y-4 end-5   z-[999]   flex items-center ">
                <label htmlFor="attach">
                  <GrAttachment color="#000000" className="cursor-pointer" />
                </label>
                <input
                  type="file"
                  className="hidden"
                  id="attach"
                  multiple
                  onChange={handleImageChange}
                />
              </div>
              <textarea
                ref={textareaRef}
                value={UserMsg}
                onChange={handleChange}
                onKeyDown={handleInputResize}
                id="email-address-icon"
                autoComplete="off"
                placeholder="Type Here"
                className={`bg-[#FFFFFF]  ${
                  textareaRef?.current?.scrollHeight > 100
                    ? "overflow-auto"
                    : "overflow-hidden"
                } custom-scroll-bar  pr-10 resize-none w-full h-[45px] border border-[#CFCFCF] text-gray-900 text-sm rounded-2xl block p-2.5 focus:outline-[#0A8A33]`}
              />
            </div>
            <div className="mt-3">
              <button
                type="submit"
                disabled={sentLoad ? sentLoad : sentLoad}
                className="text-white bg-[#0A8A33] hover:bg-green-800   rounded-full text-sm p-2.5 text-center flex items-center  "
              >
                <RiSendPlaneFill className="lg:text-2xl" />
              </button>
            </div>
          </form>
        </div>
      )}


      <DeleteMessageModal deleteModal={deleteModal} setDeleteModal={setDeleteModal} handleDelete={handleDelete} />
    </div>
  );
}
